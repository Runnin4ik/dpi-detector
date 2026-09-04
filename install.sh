#!/bin/sh
set -e

REPO="Runnin4ik/dpi-detector"
VERSION="v5.0.0-alpha.2"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
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

BIN_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARGET}"
OUT_FILE="/tmp/dpi-detector"

echo "Downloading ${TARGET} (${VERSION})..."

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BIN_URL" -o "$OUT_FILE"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$OUT_FILE" "$BIN_URL"
else
  echo "Error: neither curl nor wget found in PATH." >&2
  exit 1
fi

chmod +x "$OUT_FILE"
echo "Starting DPI Detector..."
if [ -c /dev/tty ]; then
  exec "$OUT_FILE" "$@" </dev/tty
else
  exec "$OUT_FILE" "$@"
fi
