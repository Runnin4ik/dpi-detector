#!/bin/sh
set -e

REPO="Runnin4ik/dpi-detector"
VERSION="v5.0.0-alpha.1"

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
        # Check endianness if possible
        if [ -f /bin/busybox ] && hexdump -s 5 -n 1 -e '"%d"' /bin/busybox 2>/dev/null | grep -q '1'; then
          TARGET="dpi-detector-linux-mipsel"
        else
          TARGET="dpi-detector-linux-mips"
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
