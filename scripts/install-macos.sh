#!/usr/bin/env bash
# Install the latest macOS release into ~/.local/bin. No sudo, no .app, no .desktop file.
# Default repository is rxznik/rust-vpn. RUSTVPN_REPO overrides it
# (owner/name or a github.com URL). Replaces binaries on a later run.
# Does not read or write state.db or any app data directory.
set -euo pipefail

normalize_repo() {
  local value=$1
  value="${value%.git}"
  value="${value#https://github.com/}"
  value="${value#http://github.com/}"
  value="${value#git@github.com:}"
  printf '%s' "${value}"
}

RUSTVPN_REPO="$(normalize_repo "${RUSTVPN_REPO:-rxznik/rust-vpn}")"
case "${RUSTVPN_REPO}" in
  /* | */ | */*/* | *[[:space:]]*)
    echo "RUSTVPN_REPO must look like owner/name." >&2
    exit 1
    ;;
  */*) ;;
  *)
    echo "RUSTVPN_REPO must look like owner/name." >&2
    exit 1
    ;;
esac
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "install-macos.sh is for macOS." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
  echo "tar is required." >&2
  exit 1
fi

asset="rustvpn-macos-${arch}.tar.gz"
url="https://github.com/${RUSTVPN_REPO}/releases/latest/download/${asset}"
bin_dir="${HOME}/.local/bin"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fL --retry 3 --retry-delay 2 -o "${tmp}/${asset}" "${url}"
tar -xzf "${tmp}/${asset}" -C "${tmp}"

for name in rustvpn xray rustvpn.png; do
  if [[ ! -f "${tmp}/${name}" ]]; then
    echo "archive is missing ${name}" >&2
    exit 1
  fi
done

mkdir -p "${bin_dir}"
install -m 755 "${tmp}/rustvpn" "${bin_dir}/rustvpn"
install -m 755 "${tmp}/xray" "${bin_dir}/xray"
install -m 644 "${tmp}/rustvpn.png" "${bin_dir}/rustvpn.png"

echo "Installed rustvpn and xray to ${bin_dir}"
