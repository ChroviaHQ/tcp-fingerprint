package main

import (
	"encoding/binary"
	"errors"
	"slices"
)

type Fingerprint struct {
	IPVersion   int     `json:"ip_version"`
	TTL         uint8   `json:"observed_ttl"`
	Window      uint16  `json:"window"`
	MSS         *uint16 `json:"mss,omitempty"`
	WindowScale *uint8  `json:"window_scale,omitempty"`
	Options     []int   `json:"tcp_options"`
	EOLPadding  int     `json:"eol_padding"`
}

type Result struct {
	TestID       string       `json:"test_id,omitempty"`
	ExitIP       string       `json:"exit_ip"`
	Family       string       `json:"family"`
	Rule         string       `json:"rule,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	SYNAvailable bool         `json:"syn_available"`
	Fingerprint  *Fingerprint `json:"fingerprint,omitempty"`
}

func parseSYN(b []byte) (*Fingerprint, error) {
	if len(b) < 1 {
		return nil, errors.New("empty SYN")
	}
	f := &Fingerprint{IPVersion: int(b[0] >> 4), Options: make([]int, 0, 10)}
	var off, total int
	switch f.IPVersion {
	case 4:
		if len(b) < 20 {
			return nil, errors.New("short IPv4 header")
		}
		off = int(b[0]&15) * 4
		total = int(binary.BigEndian.Uint16(b[2:4]))
		if off < 20 || off > len(b) || b[9] != 6 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return nil, errors.New("unsupported IPv4 header")
		}
		f.TTL = b[8]
	case 6:
		if len(b) < 40 {
			return nil, errors.New("short IPv6 header")
		}
		f.TTL = b[7]
		total = 40 + int(binary.BigEndian.Uint16(b[4:6]))
		off = 40
		next := b[6]
		for next != 6 {
			if off+2 > len(b) {
				return nil, errors.New("short IPv6 extension")
			}
			var n int
			switch next {
			case 0, 43, 60:
				n = (int(b[off+1]) + 1) * 8
			case 51:
				n = (int(b[off+1]) + 2) * 4
				if n < 12 {
					return nil, errors.New("invalid IPv6 authentication header")
				}
			default:
				return nil, errors.New("unsupported IPv6 extension")
			}
			if off+n > len(b) || off+n > total {
				return nil, errors.New("truncated IPv6 extension")
			}
			next = b[off]
			off += n
		}
	default:
		return nil, errors.New("unsupported IP version")
	}
	if total < off+20 || len(b) > total {
		return nil, errors.New("invalid IP packet length")
	}
	if off+20 > len(b) {
		return nil, errors.New("short TCP header")
	}
	t := b[off:]
	h := int(t[12]>>4) * 4
	if h < 20 || h > len(t) || t[13]&0x17 != 2 {
		return nil, errors.New("invalid initial SYN")
	}
	f.Window = binary.BigEndian.Uint16(t[14:16])
	var seen [256]bool
	for i := 20; i < h; {
		kind := t[i]
		f.Options = append(f.Options, int(kind))
		if kind == 0 {
			f.EOLPadding = h - i - 1
			for _, v := range t[i+1 : h] {
				if v != 0 {
					return nil, errors.New("nonzero EOL padding")
				}
			}
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > h {
			return nil, errors.New("short option")
		}
		n := int(t[i+1])
		if n < 2 || i+n > h {
			return nil, errors.New("invalid option length")
		}
		if seen[kind] {
			return nil, errors.New("duplicate TCP option")
		}
		seen[kind] = true
		switch kind {
		case 2:
			if n != 4 {
				return nil, errors.New("invalid MSS")
			}
			v := binary.BigEndian.Uint16(t[i+2 : i+4])
			if v == 0 {
				return nil, errors.New("zero MSS")
			}
			f.MSS = &v
		case 3:
			if n != 3 || t[i+2] > 14 {
				return nil, errors.New("invalid window scale")
			}
			v := t[i+2]
			f.WindowScale = &v
		case 4:
			if n != 2 {
				return nil, errors.New("invalid SACK permitted")
			}
		case 8:
			if n != 10 || binary.BigEndian.Uint32(t[i+6:i+10]) != 0 {
				return nil, errors.New("invalid SYN timestamp")
			}
		}
		i += n
	}
	return f, nil
}

func classify(f *Fingerprint) (family, rule, reason string) {
	if f.MSS == nil || f.WindowScale == nil || f.Window == 0 {
		return "unknown", "", "insufficient_features"
	}
	if slices.Equal(f.Options, []int{2, 1, 3, 1, 1, 4}) && f.TTL >= 96 && f.TTL <= 128 {
		return "windows", "windows-syn-01", ""
	}
	if slices.Equal(f.Options, []int{2, 1, 3, 1, 1, 8, 4, 0}) && f.EOLPadding == 1 && f.TTL >= 32 && f.TTL <= 64 {
		return "apple", "apple-syn-01", ""
	}
	return "unknown", "", "no_matching_rule"
}

func resultForSYN(b []byte, err error) Result {
	r := Result{Family: "unknown"}
	if err != nil {
		r.Reason = "syn_capture_failed"
		return r
	}
	if len(b) == 0 {
		r.Reason = "syn_unavailable"
		return r
	}
	r.SYNAvailable = true
	f, err := parseSYN(b)
	if err != nil {
		r.Reason = "invalid_syn: " + err.Error()
		return r
	}
	r.Fingerprint = f
	r.Family, r.Rule, r.Reason = classify(f)
	return r
}
