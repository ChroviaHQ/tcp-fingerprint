# TCP Fingerprint

A small, self-hosted HTTP service that reads TCP SYN fingerprints and returns
raw network characteristics with conservative OS-family hints.

Built by [Chrovia](https://console.getchrovia.com), a browser platform for
customized Chromium runtimes and browser automation.

## Why use it?

Inspect the TCP stack that actually connects to your server. Compare a direct
connection with a proxy exit, collect network fingerprints for diagnostics,
or integrate a JSON endpoint into your own testing tools.

- Captures the connection's initial SYN using Linux `TCP_SAVE_SYN` and
  `TCP_SAVED_SYN`.
- Reports observed TTL / IPv6 hop limit, window size, MSS, window scale,
  TCP option order, and EOL padding.
- Returns `windows`, `apple`, or `unknown` using a small, explicit rule set.
- Uses only the Go standard library: no libpcap, packet-capture daemon, or
  external Go dependencies.
- Builds static Linux binaries for amd64 and arm64.

This is a diagnostic tool, not proof of an operating system or identity.
It does not fingerprint TLS, HTTP headers, JavaScript, or browser APIs.

## Quick start

Run on Linux with Go 1.23 or newer and a kernel that supports `TCP_SAVE_SYN`
and `TCP_SAVED_SYN`. From this project's directory:

```bash
go build -trimpath -o dist/tcp-fingerprint .
./dist/tcp-fingerprint -listen :38473
```

In another terminal:

```bash
curl 'http://127.0.0.1:38473/healthz'
curl 'http://127.0.0.1:38473/detect?test_id=local-check'
```

A loopback request measures the server's own TCP stack. Use a separate client
to measure an external connection.

The default address is `:38473`. Override it with `-listen`; the service does
not read a `PORT` environment variable. Root is not required for the default
port. The runtime is Linux-only; macOS and Windows can cross-compile binaries.

## Deployment

The incoming TCP connection must reach this service without a proxy terminating
and recreating it:

```text
Client or proxy exit ── TCP connection ──> Linux host ──> TCP Fingerprint
```

Use a Linux host with a publicly reachable port. Allow inbound TCP traffic on
that port in your host firewall and cloud security group.

Do not place a CDN, HTTP reverse proxy, or connection-terminating TCP proxy in
front of the service. You would measure that intermediary's SYN instead of
the original peer's. Public proxy ingress such as Railway's HTTP or TCP Proxy
is therefore unsuitable for measuring the original peer with this design.
Forwarded IP headers and PROXY protocol cannot restore the original SYN.

Packet forwarding / NAT may preserve the TCP handshake, but network devices can
still change fields such as MSS and TTL. Check your actual network path.

### Build distribution files

With Go and Node.js installed, run:

```bash
npm run build
```

No `npm install` is needed. The build produces:

```text
dist/
  tcp-fingerprint-linux-amd64
  tcp-fingerprint-linux-arm64
  install.sh
  LICENSE
  README.md
  CONTRIBUTING.md
  SECURITY.md
```

### Install on Ubuntu with systemd

Copy the matching binary and `install.sh` from `dist/` to the same directory on
your Ubuntu server, then run:

```bash
sudo bash install.sh
```

Or specify the binary and a port between 1024 and 65535:

```bash
sudo bash install.sh ./tcp-fingerprint-linux-amd64 38473
```

The installer installs `/usr/local/bin/tcp-fingerprint`, creates and enables
`tcp-fingerprint.service`, and checks `/healthz`. It uses a systemd dynamic user
with an empty capability bounding set. Re-running it replaces the binary and
restarts the service. It does not modify firewall rules.

```bash
sudo systemctl status tcp-fingerprint
sudo journalctl -u tcp-fingerprint -f
```

To uninstall:

```bash
sudo systemctl disable --now tcp-fingerprint
sudo rm /etc/systemd/system/tcp-fingerprint.service
sudo rm /usr/local/bin/tcp-fingerprint
sudo systemctl daemon-reload
```

## HTTP API

### `GET /healthz`

Returns `200 OK` with `ok` followed by a newline. This checks HTTP availability,
not successful SYN capture or classification.

### `GET /detect`

Returns JSON with `Cache-Control: no-store`. Optional `test_id` is echoed back;
it must be valid UTF-8 and no more than 128 bytes. Invalid query input returns
`400`.

Illustrative response for a matching Windows-style SYN:

```json
{
  "test_id": "proxy-check",
  "exit_ip": "203.0.113.10",
  "family": "windows",
  "rule": "windows-syn-01",
  "syn_available": true,
  "fingerprint": {
    "ip_version": 4,
    "observed_ttl": 117,
    "window": 64240,
    "mss": 1460,
    "window_scale": 8,
    "tcp_options": [2, 1, 3, 1, 1, 4],
    "eol_padding": 0
  }
}
```

| Field | Meaning |
| --- | --- |
| `exit_ip` | Socket peer IP, without the port. Forwarded headers are not used. |
| `family` | `windows`, `apple`, or `unknown`. |
| `rule` | Matching rule ID; omitted when no rule matches. |
| `reason` | Explanation for an unknown result; omitted on a match. |
| `syn_available` | Whether nonempty SYN data was obtained; parsing can still fail. |
| `fingerprint` | Parsed fields; omitted if capture or parsing fails. |
| `test_id` | Caller-provided identifier; omitted if empty. |

`observed_ttl` is the received IPv4 TTL or IPv6 hop limit, not an inferred
initial value. `mss` and `window_scale` are omitted when their options are absent.
TCP options are numeric kinds in wire order, including NOP (`1`) and EOL (`0`).

Unknown results use one of these reasons:

| Reason | Meaning |
| --- | --- |
| `syn_capture_failed` | Reading saved SYN data failed. |
| `syn_unavailable` | The kernel returned no SYN data. |
| `invalid_syn: …` | The packet could not be parsed or is unsupported. |
| `insufficient_features` | MSS or window scale is missing, or the window is zero. |
| `no_matching_rule` | Parsed features do not match a supported rule. |

These diagnostic results still return HTTP `200`. Clients must inspect
`syn_available`, `family`, and `reason`. Missing connection context returns
`503`.

## Classification limits

The current rules require MSS, window scale, and a nonzero window, then match:

| Family | TCP option order | Observed TTL / hop limit | Additional condition |
| --- | --- | --- | --- |
| `windows` | `2,1,3,1,1,4` | 96–128 | — |
| `apple` | `2,1,3,1,1,8,4,0` | 32–64 | One byte of EOL padding |

`apple` does not distinguish macOS from iOS. Linux, Android, and BSD do not
currently have dedicated rules. `unknown` means unrecognized, not “Unix-like”:
unrecognized Windows and Apple configurations also reach this result.

Fingerprints can be modified or imitated. If a proxy creates the outbound
connection, the service measures the proxy exit's TCP stack, not the browser
behind it. HTTP keep-alive requests on one connection share the same captured
fingerprint.

The server currently provides plain HTTP only, with no built-in authentication,
rate limiting, or CORS headers. A browser page served over HTTPS may be unable
to call it because of mixed-content and cross-origin restrictions. Adding a
TLS-terminating reverse proxy would change the measured TCP peer; direct TLS
support would need to be implemented in the service.

## Development

On Linux:

```bash
gofmt -w .
go vet ./...
go build ./...
```

The standalone GitHub workflow uses the stable Go toolchain, checks formatting
and installer syntax, runs vet, and uploads both Linux binaries plus the
installer and documentation as a build artifact. It runs when this directory
is published as the repository root. Extract the artifact before running
the installer; it applies executable permissions to the installed binary.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

[MIT](LICENSE). Copyright 2026 Chrovia Labs.
