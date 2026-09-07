#!/bin/sh
set -e

main() {
  REPO="Runnin4ik/dpi-detector"
  VERSION="${DPI_VERSION:-v5.0.0-alpha.7}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    # Check if running on Android (Termux, ADB shell, Android terminal)
    is_android=""
    if [ -n "${TERMUX_VERSION:-}" ] || [ -f "/system/bin/getprop" ] || [ "$(uname -o 2>/dev/null)" = "Android" ]; then
      is_android="1"
    fi

    if [ -n "$is_android" ]; then
      case "$ARCH" in
        aarch64|arm64)
          TARGET="dpi-detector-android-arm64"
          ;;
        armv7*|armv8l*|armhf|arm)
          TARGET="dpi-detector-android-armv7"
          ;;
        x86_64|amd64)
          TARGET="dpi-detector-linux-x86_64"
          ;;
        *)
          echo "Unsupported Android architecture: $ARCH" >&2
          exit 1
          ;;
      esac
    else
      case "$ARCH" in
        x86_64|amd64)
          TARGET="dpi-detector-linux-x86_64"
          ;;
        aarch64|arm64)
          TARGET="dpi-detector-linux-arm64"
          ;;
        armv7*|armv6*|armhf)
          TARGET="dpi-detector-linux-armv7"
          ;;
        mipsel*|mips*el*)
          TARGET="dpi-detector-linux-mipsel"
          ;;
        mips*)
          # uname -m reports "mips" for BOTH endians. Check the kernel byte
          # order first, then fall back to ELF EI_DATA of a system binary.
          # busybox hexdump lacks -e, so use od (POSIX) for the fallback.
          mips_endian=""
          if grep -qi "little endian" /proc/cpuinfo 2>/dev/null; then
            mips_endian="le"
          elif grep -qi "big endian" /proc/cpuinfo 2>/dev/null; then
            mips_endian="be"
          else
            for _b in /bin/busybox /bin/sh /bin/ls; do
              if [ -f "$_b" ]; then
                _ei=$(od -A n -t u1 -j 5 -N 1 "$_b" 2>/dev/null | tr -d ' ')
                if [ "$_ei" = "1" ]; then mips_endian="le"; break; fi
                if [ "$_ei" = "2" ]; then mips_endian="be"; break; fi
              fi
            done
          fi
          if [ "$mips_endian" = "be" ]; then
            TARGET="dpi-detector-linux-mips"
          else
            # Little-endian (MediaTek, Realtek, modern Qualcomm) is the
            # common case; default to it when detection is inconclusive.
            TARGET="dpi-detector-linux-mipsel"
          fi
          ;;
        *)
          echo "Unsupported Linux architecture: $ARCH" >&2
          exit 1
          ;;
      esac
    fi
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64)
        TARGET="dpi-detector-macos-arm64"
        ;;
      x86_64)
        TARGET="dpi-detector-macos-intel"
        ;;
      *)
        echo "Unsupported macOS architecture: $ARCH" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported operating system: $OS" >&2
    exit 1
    ;;
esac

# Determine target installation directory:
# 1. /opt/bin (Keenetic, OpenWrt, Entware routers - persists across reboots)
# 2. /usr/local/bin (Standard Linux with root/sudo)
# 3. $TMPDIR, /tmp, $HOME, or current directory
pick_install_dir() {
  if [ -n "${DPI_INSTALL_DIR:-}" ] && [ -d "$DPI_INSTALL_DIR" ] && [ -w "$DPI_INSTALL_DIR" ]; then
    echo "$DPI_INSTALL_DIR"
    return 0
  fi
  if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && [ -w "${PREFIX}/bin" ]; then
    echo "${PREFIX}/bin"
    return 0
  fi
  if [ -d /opt/bin ] && [ -w /opt/bin ]; then
    echo "/opt/bin"
    return 0
  fi
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
    return 0
  fi
  for _d in "${TMPDIR:-}" /tmp "$HOME" .; do
    [ -n "$_d" ] || continue
    if [ -d "$_d" ] && touch "$_d/.dpi-wtest.$$" 2>/dev/null; then
      rm -f "$_d/.dpi-wtest.$$"
      echo "$_d"
      return 0
    fi
  done
  return 1
}

OUT_DIR=$(pick_install_dir) || {
  echo "Error: no writable directory found (tried /opt/bin, /usr/local/bin, \$TMPDIR, /tmp, \$HOME, .)." >&2
  exit 1
}

OUT_FILE="${OUT_DIR}/dpi-detector"
TMP_FILE="${OUT_DIR}/.dpi-detector.tmp.$$"

# Helper: check if target has a UPX-compressed build available in releases
target_supports_upx() {
  case "$1" in
    dpi-detector-linux-x86_64|\
    dpi-detector-linux-arm64|\
    dpi-detector-linux-armv7|\
    dpi-detector-linux-mipsel|\
    dpi-detector-linux-mips)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# Helper: query available disk space in KB for target install directory
get_avail_kb() {
  _check_dir="$1"
  _df_out=$(df -k -P "$_check_dir" 2>/dev/null || df -k "$_check_dir" 2>/dev/null || true)
  [ -z "$_df_out" ] && return 0
  _last_line=$(echo "$_df_out" | tail -n 1)
  set -- $_last_line
  if [ -n "${4:-}" ] && [ "$4" -eq "$4" ] 2>/dev/null; then
    echo "$4"
  elif [ -n "${3:-}" ] && [ "$3" -eq "$3" ] 2>/dev/null; then
    echo "$3"
  fi
}

# Determine primary and fallback targets (UPX vs standard):
# 1. Explicit user override via DPI_UPX (1/force vs 0/never)
# 2. Auto-detection: if free disk space < 7 MB (7168 KB), prioritize compact UPX (~1.4 MB)
BASE_TARGET="$TARGET"
PRIMARY_TARGET="$BASE_TARGET"
FALLBACK_TARGET=""

if target_supports_upx "$BASE_TARGET"; then
  case "${DPI_UPX:-auto}" in
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Ff][Oo][Rr][Cc][Ee])
      PRIMARY_TARGET="${BASE_TARGET}-upx"
      FALLBACK_TARGET="${BASE_TARGET}"
      echo "Notice: DPI_UPX enabled. Preferring compact UPX-compressed binary (~1.4 MB)."
      ;;
    0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Nn][Ee][Vv][Ee][Rr])
      PRIMARY_TARGET="${BASE_TARGET}"
      FALLBACK_TARGET=""
      ;;
    auto|*)
      AVAIL_KB=$(get_avail_kb "$OUT_DIR")
      if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 7168 ]; then
        PRIMARY_TARGET="${BASE_TARGET}-upx"
        FALLBACK_TARGET="${BASE_TARGET}"
        AVAIL_MB=$((AVAIL_KB / 1024))
        echo "Notice: low disk space in ${OUT_DIR} (~${AVAIL_MB} MB free, threshold 7 MB)."
        echo "        Automatically selecting compact UPX-compressed binary (~1.4 MB)."
      else
        PRIMARY_TARGET="${BASE_TARGET}"
        FALLBACK_TARGET="${BASE_TARGET}-upx"
      fi
      ;;
  esac
fi

download_file() {
  _url="$1"
  _dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 4 --max-time 120 "$_url" -o "$_dest" 2>/dev/null || \
    curl -kfsSL --connect-timeout 4 --max-time 120 "$_url" -o "$_dest" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=4 -O "$_dest" "$_url" 2>/dev/null || \
    wget -q --no-check-certificate --timeout=4 -O "$_dest" "$_url" 2>/dev/null
  else
    echo "Error: neither curl nor wget found in PATH." >&2
    exit 1
  fi
}

build_url_list() {
  _tgt="$1"
  _list=""
  if [ -n "${DPI_MIRRORS:-}" ]; then
    for _m in $DPI_MIRRORS; do
      _list="${_list} ${_m%/}/${_tgt}"
    done
  fi

  if [ "$VERSION" = "latest" ]; then
    _gh="https://github.com/${REPO}/releases/latest/download/${_tgt}"
  else
    _gh="https://github.com/${REPO}/releases/download/${VERSION}/${_tgt}"
  fi

  _list="${_list} ${_gh}"
  _list="${_list} https://ghfast.top/${_gh}"
  _list="${_list} https://ghproxy.net/${_gh}"
  _list="${_list} https://gh-proxy.com/${_gh}"
  _list="${_list} https://ghproxy.vip/${_gh}"
  _list="${_list} https://gh-proxy.org/${_gh}"
  _list="${_list} https://github.boki.moe/${_gh}"
  echo "$_list"
}

try_download_and_verify() {
  _tgt="$1"
  echo "Downloading ${_tgt} (${VERSION}) to ${OUT_FILE}..."
  _urls=$(build_url_list "$_tgt")
  for _url in $_urls; do
    echo "Fetching from: ${_url} ..."
    rm -f "$TMP_FILE" 2>/dev/null || true
    if download_file "$_url" "$TMP_FILE" && [ -s "$TMP_FILE" ]; then
      chmod +x "$TMP_FILE"
      if _ver=$("$TMP_FILE" --version 2>&1); then
        echo "Verified: ${_ver}"
        return 0
      else
        echo "Warning: binary failed architecture/runtime check, trying next mirror..." >&2
        rm -f "$TMP_FILE" 2>/dev/null || true
      fi
    else
      rm -f "$TMP_FILE" 2>/dev/null || true
    fi
  done
  return 1
}

DOWNLOADED=0
CHOSEN_TARGET="$PRIMARY_TARGET"

if try_download_and_verify "$PRIMARY_TARGET"; then
  DOWNLOADED=1
  CHOSEN_TARGET="$PRIMARY_TARGET"
elif [ -n "$FALLBACK_TARGET" ]; then
  echo "Notice: could not download or verify ${PRIMARY_TARGET}."
  echo "        Attempting fallback to ${FALLBACK_TARGET}..."
  if try_download_and_verify "$FALLBACK_TARGET"; then
    DOWNLOADED=1
    CHOSEN_TARGET="$FALLBACK_TARGET"
  fi
fi

if [ "$DOWNLOADED" -ne 1 ]; then
  echo "Error: failed to download working binary (${PRIMARY_TARGET}${FALLBACK_TARGET:+ / $FALLBACK_TARGET}) from all mirrors." >&2
  exit 1
fi
# Atomic install: replace destination file with verified temp binary
mv -f "$TMP_FILE" "$OUT_FILE"
chmod +x "$OUT_FILE"
RUN_FILE="$OUT_FILE"
CMD_RUN="${RUN_FILE}"
case ":$PATH:" in
  *":${OUT_DIR}:"*)
    CMD_RUN="dpi-detector"
    ;;
esac

echo ""
echo "=============================================="
echo "  DPI Detector successfully installed!"
echo "  Location: ${RUN_FILE}"
case "$CHOSEN_TARGET" in
  *-upx)
    echo "  Variant:  Compact UPX (~1.4 MB)"
    ;;
  *)
    echo "  Variant:  Standard (~3.9 MB)"
    ;;
esac
echo "=============================================="
echo ""
echo "To start the interactive menu:"
echo "  ${CMD_RUN}"
echo ""
echo "Quick test:"
echo "  ${CMD_RUN} -t 1"
echo ""
echo "All tests:"
echo "  ${CMD_RUN} -t 12345"
echo ""

# Only run automatically if user explicitly passed arguments (e.g. sh -s -- -t 1)
if [ $# -gt 0 ]; then
  exec "$RUN_FILE" "$@"
fi
}

main "$@"
