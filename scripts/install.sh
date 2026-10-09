#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

[[ $# -le 2 ]] || fail "Usage: sudo bash install.sh [binary] [port]"
[[ $(uname -s) == Linux ]] || fail "Run this installer on the Ubuntu server."
[[ $EUID -eq 0 ]] || fail "Run with sudo bash install.sh [binary] [port]."
[[ -f /etc/os-release ]] || fail "Cannot identify the operating system."
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || fail "This installer requires Ubuntu."
[[ -d /run/systemd/system ]] || fail "systemd must be running."
command -v ss >/dev/null || fail "The ss command from iproute2 is required."
exec 9>/run/lock/tcp-fingerprint-install.lock
flock -n 9 || fail "Another installation is already running."

case "$(uname -m)" in
  x86_64) arch=amd64; machine=62 ;;
  aarch64) arch=arm64; machine=183 ;;
  *) fail "Unsupported architecture: $(uname -m)" ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary=${1:-$script_dir/tcp-fingerprint-linux-$arch}
port=${2:-38473}
[[ $port =~ ^[0-9]{1,5}$ ]] || fail "Port must be a number between 1024 and 65535."
port=$((10#$port))
((port >= 1024 && port <= 65535)) || fail "Port must be between 1024 and 65535."
[[ -f $binary && -r $binary ]] || fail "Binary not found: $binary"
magic=$(od -An -tx1 -N6 -- "$binary" | tr -d ' \n')
[[ $magic == 7f454c460201 ]] || fail "Expected a 64-bit little-endian Linux ELF binary."
elf_machine=$(od -An -tu2 -j18 -N2 -- "$binary" | tr -d ' \n')
[[ $elf_machine == "$machine" ]] || fail "Binary architecture does not match linux/$arch."
service_pid=$(systemctl show -p MainPID --value tcp-fingerprint.service 2>/dev/null || true)
listeners=$(ss -H -ltnp "sport = :$port")
while IFS= read -r listener; do
  [[ -z $listener ]] && continue
  [[ $service_pid =~ ^[1-9][0-9]*$ && $listener == *"pid=$service_pid,"* ]] || fail "Port $port is already occupied by another process."
done <<< "$listeners"

install -d -m 0755 /usr/local/bin
binary_temp=$(mktemp /usr/local/bin/.tcp-fingerprint.XXXXXX)
unit_temp=''
trap 'rm -f -- "$binary_temp"; if [[ -n $unit_temp ]]; then rm -f -- "$unit_temp"; fi' EXIT
install -m 0755 -- "$binary" "$binary_temp"
"$binary_temp" -h >/dev/null 2>&1 || fail "Binary cannot run on this server."
unit_temp=$(mktemp /etc/systemd/system/.tcp-fingerprint.XXXXXX)
cat > "$unit_temp" <<EOF
[Unit]
Description=TCP fingerprint service
After=network.target

[Service]
Type=exec
DynamicUser=yes
ExecStart=/usr/local/bin/tcp-fingerprint -listen :$port
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit_temp"
mv -f -- "$binary_temp" /usr/local/bin/tcp-fingerprint
mv -f -- "$unit_temp" /etc/systemd/system/tcp-fingerprint.service
systemctl daemon-reload
systemctl enable tcp-fingerprint.service
systemctl reset-failed tcp-fingerprint.service
if ! systemctl restart tcp-fingerprint.service; then
  journalctl -u tcp-fingerprint.service -n 30 --no-pager >&2
  fail "Service failed to start."
fi

for ((attempt=0; attempt<20; attempt++)); do
  service_pid=$(systemctl show -p MainPID --value tcp-fingerprint.service)
  listeners=$(ss -H -ltnp "sport = :$port")
  if [[ $service_pid != 0 && $listeners == *"pid=$service_pid,"* ]] && systemctl is-active --quiet tcp-fingerprint.service && timeout 2 bash -c '
    exec 3<>/dev/tcp/127.0.0.1/$1
    printf "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3
    IFS= read -r status <&3
    [[ $status == "HTTP/1.1 200 "* ]]
  ' bash "$port" 2>/dev/null; then
    printf 'Installed and running: http://SERVER_IP:%s/detect\n' "$port"
    printf 'Allow TCP %s in your cloud security group and server firewall.\n' "$port"
    printf 'Logs: sudo journalctl -u tcp-fingerprint -f\n'
    exit 0
  fi
  sleep 1
done

journalctl -u tcp-fingerprint.service -n 30 --no-pager >&2
fail "Service did not become healthy."
