#!/usr/bin/env bash
set -Eeuo pipefail
# WBIT Chat History Ubuntu 26.04 bootstrap. Does NOT edit Outreach, WBIT Control, or Runner.
PAYLOAD_URL='https://raw.githubusercontent.com/wiredbyteit/Cleanup/f83601aff76372117db5658b60f2c06c191bbd46/wbit-chat-history-ubuntu2604/history-vm-files.tar.gz.b64'
PAYLOAD_SHA256='c6468a5a012275e453508cd7639c75fe2341fc0bd397dce6d02fc0dcf52ee0fc'
if [ "${EUID}" -ne 0 ]; then
  echo 'Run the installer using sudo, e.g. curl ... | sudo bash' >&2
  exit 2
fi
if [ ! -r /etc/os-release ]; then echo 'Ubuntu 26.04 required' >&2; exit 2; fi
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [[ "${VERSION_ID:-}" != 26.04* ]]; then
  echo "Ubuntu 26.04 required, found: ${PRETTY_NAME:-unknown}" >&2
  exit 2
fi
if [ -e /opt/wbit-control ] || [ -e /opt/wbit-41-cumulative-closeout ]; then
  echo 'Existing WBIT controller found on this machine; refusing' >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
tempdir="$(mktemp -d -t wbit-history-install-XXXXXXXX)"
trap 'rm -rf "$tempdir"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 2 --connect-timeout 15 --max-time 180 "$PAYLOAD_URL" --output "$tempdir/payload.b64"
else
  wget --https-only --quiet --tries=3 --timeout=90 -O "$tempdir/payload.b64" "$PAYLOAD_URL"
fi
base64 --decode "$tempdir/payload.b64" > "$tempdir/history-vm-files.tar.gz"
printf '%s  %s\n' "$PAYLOAD_SHA256" "$tempdir/history-vm-files.tar.gz" | sha256sum --check --status || { echo 'Payload integrity check FAILED; refusing installation' >&2; exit 5; }
tar -xzf "$tempdir/history-vm-files.tar.gz" -C "$tempdir" --no-same-owner --no-same-permissions
cd "$tempdir/WBIT-Chat-History-VM-26.04"
echo 'Verified WBIT Chat History VM installation package.'
bash ./install-ubuntu-26.04.sh
echo
echo 'Installation complete; checking local API:'
bash /opt/wbit-chat-history/verify.sh
