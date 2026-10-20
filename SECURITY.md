# Security

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** option when private
vulnerability reporting is enabled.

If it is unavailable, open an issue asking maintainers for a private reporting
channel without including exploit details, sensitive logs, or affected hosts.
Share those details only after a private channel is established.

Include the affected revision, Linux kernel version, reproduction steps, and
impact. No response-time guarantee or formal support window is currently
published.

## Deployment considerations

The service exposes plain HTTP without authentication or rate limiting.
Responses contain the connecting peer's IP and network fingerprint. Avoid
sending secrets in `test_id`, and consider where diagnostic responses and
access logs are stored.

OS-family results are heuristics and must not be used as an authentication or
authorization boundary. Intermediaries and crafted packets can alter results.

Use host-level network controls appropriate to your deployment. A reverse proxy
that establishes a new TCP connection changes the fingerprint being measured.
