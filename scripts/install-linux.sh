#!/usr/bin/env bash
# Install the latest Linux release into the user account. No sudo.
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

quote_desktop_exec() {
  local value=$1
  local out="" i char
  local len=${#value}
  for ((i = 0; i < len; i++)); do
    char=${value:i:1}
    case ${char} in
      '\' | '"' | '$' | '`') out="${out}\\${char}" ;;
      *) out="${out}${char}" ;;
    esac
  done
  printf '%s' "${out}"
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
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux.sh is for Linux." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  *)
    machine="$(uname -m)"
    case "${machine}" in
      aarch64 | arm64) asset="rustvpn-linux-aarch64.tar.gz" ;;
      *) asset="rustvpn-linux-${machine}.tar.gz" ;;
    esac
    echo "This release does not publish ${asset}. Only rustvpn-linux-x86_64.tar.gz is built." >&2
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

asset="rustvpn-linux-${arch}.tar.gz"
url="https://github.com/${RUSTVPN_REPO}/releases/latest/download/${asset}"
bin_dir="${HOME}/.local/bin"
icon_dir="${HOME}/.local/share/icons/hicolor/256x256/apps"
apps_dir="${HOME}/.local/share/applications"
rustvpn_bin="${bin_dir}/rustvpn"

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

mkdir -p "${bin_dir}" "${icon_dir}" "${apps_dir}"
install -m 755 "${tmp}/rustvpn" "${rustvpn_bin}"
install -m 755 "${tmp}/xray" "${bin_dir}/xray"
install -m 644 "${tmp}/rustvpn.png" "${icon_dir}/rustvpn.png"

exec_quoted="$(quote_desktop_exec "${rustvpn_bin}")"
{
  printf '%s\n' '[Desktop Entry]'
  printf '%s\n' 'Type=Application'
  printf '%s\n' 'Name=rustvpn'
  printf 'Exec="%s"\n' "${exec_quoted}"
  printf '%s\n' 'Icon=rustvpn'
  printf '%s\n' 'Terminal=false'
  printf '%s\n' 'Categories=Network;'
} >"${apps_dir}/rustvpn.desktop"

echo "Installed rustvpn and xray to ${bin_dir}"
