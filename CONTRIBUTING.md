# Contributing

Bug reports, reproducible SYN samples, documentation improvements, and focused
pull requests are welcome.

## Local setup

Use Linux with Go 1.23 or newer to run the service. Node.js is needed only for
the distribution build script. There are no external Go or npm dependencies.

```bash
gofmt -w .
go vet ./...
npm run build
```

macOS and Windows can run the distribution build, but cannot run the Linux
service. Validate runtime changes on Linux.

## Reporting a bug

Include the server architecture, Linux kernel and Go versions, command used,
network path (direct, NAT, VPN, or proxy), expected behavior, and actual JSON
response. Remove personal IP addresses and identifiers before posting logs.

Report security vulnerabilities using [SECURITY.md](SECURITY.md).

## Changing classification rules

Keep rules conservative and explain the evidence behind a proposed match.
Include the known source OS and version, raw SYN bytes or a reproducible
sanitized fixture, parsed fields, and network topology. Do not identify an OS
solely because another rule failed to match.

Document how parser or classifier changes were verified, including malformed
input and potential false positives where relevant. Preserve `unknown` for
inconclusive cases. Avoid claiming detection accuracy without measured evidence.

## Pull requests

Explain the problem, resulting behavior, and checks performed. Keep unrelated
changes separate. Update the README when API fields, rules, or deployment
requirements change. Contributions are provided under the project's MIT
license.
