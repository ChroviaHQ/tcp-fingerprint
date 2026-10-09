package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

const tcpSaveSYN = 27
const tcpSavedSYN = 28

func listenTCP(ctx context.Context, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) { sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpSaveSYN, 1) }); err != nil {
			return err
		}
		return sockErr
	}}
	return lc.Listen(ctx, "tcp", address)
}

func savedSYN(c net.Conn) ([]byte, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return nil, errors.New("expected TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 256)
	var n uint32
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		for {
			n = uint32(len(b))
			_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, tcpSavedSYN, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0)
			if errno == syscall.EINVAL && n > uint32(len(b)) && n <= 65575 {
				b = make([]byte, n)
				continue
			}
			if errno != 0 {
				sockErr = errno
			}
			break
		}
	})
	if err != nil {
		return nil, err
	}
	if sockErr != nil {
		return nil, sockErr
	}
	if n > uint32(len(b)) {
		return nil, errors.New("invalid saved SYN length")
	}
	return b[:n], nil
}
