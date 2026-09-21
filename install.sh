#!/bin/sh
set -e

main() {
  REPO="Runnin4ik/dpi-detector"
  VERSION="${DPI_VERSION:-v5.0.0-alpha.19}"

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
        armv6*)
          # The release ships armv7-unknown-linux-musleabihf, and an ARMv6 core
          # (Raspberry Pi 1, Zero, Zero W) has neither Thumb-2 nor VFPv3-D16, so
          # the binary dies on its first instruction. The run check below would
          # catch that as "failed architecture/runtime check" and the install
          # would end up blaming the mirrors, so the reason is said here.
          echo "Error: ${ARCH} cannot run the ARMv7 build this release ships." >&2
          echo "       Raspberry Pi 1 / Zero / Zero W are not supported targets." >&2
          exit 1
          ;;
        armv7*|armhf)
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
  if [ -n "${DPI_INSTALL_DIR:-}" ]; then
    # A named directory wins, and is created when it is not there yet: the user
    # said where to install, so passing it over because a parent did not exist
    # would install somewhere they did not ask for. One that still cannot be
    # used is named out loud rather than skipped in silence.
    mkdir -p "$DPI_INSTALL_DIR" 2>/dev/null || true
    if [ -d "$DPI_INSTALL_DIR" ] && [ -w "$DPI_INSTALL_DIR" ]; then
      echo "$DPI_INSTALL_DIR"
      return 0
    fi
    echo "Warning: DPI_INSTALL_DIR=${DPI_INSTALL_DIR} is not a writable directory; looking for another one." >&2
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

# The release publishes `SHA256SUMS.txt` beside the binaries and every download
# is checked against it before it is executed. What that catches is a file that
# is not what was published: a mirror that truncated it, a proxy that rewrote a
# byte, a CDN still serving an older build. What it cannot catch is a mirror that
# serves a manifest of its own — the manifest travels the same channels as the
# binary, so this is an integrity check and not a signature, and running
# `--version` stays the check that the file is a working binary. A release from
# before the manifest existed simply has none, and then the check is skipped with
# one warning instead of failing an install that would otherwise work.
MANIFEST_FILE="${OUT_DIR}/.dpi-detector.sums.$$"
# Seconds for one attempt at the manifest. It is a couple of hundred bytes, so the
# budget only ever decides how long a source that does not answer is waited for:
# the binary's 120 s would let one stall hold the install for minutes, and the
# manifest is fetched after the binary is already on disk, so that wait is dead
# time in front of the user.
MANIFEST_MAX_TIME=5
# "" until the manifest has been looked for, then "ok" or "missing".
MANIFEST_STATE=""
# The URL that produced the file being checked — the race's winner, or the mirror
# the sequential loop is on. The manifest is looked for beside it as well as at
# the release URL itself.
FETCHED_URL=""
# Set by the checksum check for the summary line: "verified" or "not checked".
CHECKSUM_RESULT="not checked"

# Filled in by the race while it runs. The race directory holds one copy per
# mirror at once — tens of megabytes — which on a router is the whole free space
# of `/opt`, so an interrupted install must not leave it behind.
RACE_DIR=""
# The race's workers while it runs, empty outside it. An interrupt has to stop
# them before the directory they write into is removed: their own traps are what
# stop the downloads they started, and those fire only when they are signalled.
RACE_PIDS=""

# Nothing this script wrote may outlive it: without this an interrupted run
# leaves the race directory in the install directory (the next run's space check
# would then refuse the race) or a half-written binary beside the real one.
# `EXIT` is asked for by name and ignored when the shell does not know it —
# BusyBox hush has the signal traps but not every build has the pseudo-signal.
cleanup() {
  if [ -n "${RACE_DIR:-}" ]; then
    rm -rf "$RACE_DIR" 2>/dev/null
    RACE_DIR=""
  fi
  if [ -n "${TMP_FILE:-}" ]; then
    rm -f "$TMP_FILE" 2>/dev/null
  fi
  if [ -n "${MANIFEST_FILE:-}" ]; then
    rm -f "$MANIFEST_FILE" 2>/dev/null
  fi
  return 0
}

stop_workers() {
  if [ -n "${RACE_PIDS:-}" ]; then
    for _p in $RACE_PIDS; do
      kill "$_p" 2>/dev/null || true
    done
    RACE_PIDS=""
  fi
  return 0
}

# `cleanup` alone is not enough for the race: a signal sent to this shell does
# not reach the workers (a Ctrl-C from the terminal does, because it goes to the
# whole foreground group, but nothing guarantees the caller used one). The
# download this shell started itself is stopped here for a different reason:
# `run_downloader` backgrounds it, and a shell without job control sets SIGINT to
# be ignored in the commands it backgrounds, so the Ctrl-C that reaches this
# script does not reach that download (`stop_downloader`, below).
trap 'cleanup' EXIT 2>/dev/null || true
trap 'stop_workers; stop_downloader; cleanup; exit 130' INT
trap 'stop_workers; stop_downloader; cleanup; exit 143' TERM
trap 'stop_workers; stop_downloader; cleanup; exit 129' HUP

# Helper: check if target has a UPX-compressed build available in releases
target_supports_upx() {
  case "$1" in
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
# 2. Auto-detection: if free disk space < 200 MB (204800 KB), prioritize the
#    compact UPX build. The threshold is a policy number, not a fit check: a
#    router's `/opt` or a `/tmp` install has little room to spare, and the
#    compact build costs nothing but the packing (it is verified by running it
#    before it is installed, and falls back to the standard build if it does not
#    start).
BASE_TARGET="$TARGET"
PRIMARY_TARGET="$BASE_TARGET"
FALLBACK_TARGET=""

if target_supports_upx "$BASE_TARGET"; then
  case "${DPI_UPX:-auto}" in
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Ff][Oo][Rr][Cc][Ee])
      PRIMARY_TARGET="${BASE_TARGET}-upx"
      FALLBACK_TARGET="${BASE_TARGET}"
      echo "Notice: DPI_UPX enabled. Preferring the compact UPX-compressed build."
      ;;
    0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Nn][Ee][Vv][Ee][Rr])
      PRIMARY_TARGET="${BASE_TARGET}"
      FALLBACK_TARGET=""
      ;;
    auto|*)
      AVAIL_KB=$(get_avail_kb "$OUT_DIR")
      if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 204800 ]; then
        PRIMARY_TARGET="${BASE_TARGET}-upx"
        FALLBACK_TARGET="${BASE_TARGET}"
      else
        PRIMARY_TARGET="${BASE_TARGET}"
        FALLBACK_TARGET="${BASE_TARGET}-upx"
      fi
      ;;
  esac
fi

# One downloader invocation, in the background with its PID kept in
# `DOWNLOAD_PID`. A signal sent to the shell that started a download does not
# reach the download itself: the shell dies, curl/wget — its child — is
# reparented and keeps pulling until its own `--max-time`. Whoever stops such a
# shell has to stop this PID too: a race worker does it in its own trap, and this
# script does it in the signal traps above (`stop_downloader`).
#
# The budget is enforced here as well as in the tools' own flags, because their
# flags are not a bound. Measured against an address the kernel drops: GNU wget
# with `--timeout=120` was still running after 442 s (it retries on its own,
# twenty times, each retry paying the full timeout again), and BusyBox wget's
# `-T` is a read timeout — its connect phase is the applet's own business, and
# it took 132 s there. `wait` cannot be given a deadline in POSIX sh, so a
# watchdog subshell sleeps the budget and kills the download if it is still
# there. It kills only while this shell lives — `$$` is the main shell, not the
# subshell — because a watchdog orphaned by an interrupted install must not fire
# at a PID that has been recycled since.
DOWNLOAD_PID=""
WATCHDOG_PID=""
# Seconds for one attempt, watchdog included; `download_file` sets it from the
# caller's budget, and this default only covers a call that forgets to.
DOWNLOAD_BUDGET=123
run_downloader() {
  "$@" &
  DOWNLOAD_PID=$!
  (
    sleep "$DOWNLOAD_BUDGET"
    kill -0 "$$" 2>/dev/null || exit 0
    kill "$DOWNLOAD_PID" 2>/dev/null
  ) &
  WATCHDOG_PID=$!
  _rc=0
  wait "$DOWNLOAD_PID" || _rc=$?
  kill "$WATCHDOG_PID" 2>/dev/null || true
  WATCHDOG_PID=""
  return "$_rc"
}

stop_downloader() {
  if [ -n "${DOWNLOAD_PID:-}" ]; then
    kill "$DOWNLOAD_PID" 2>/dev/null || true
  fi
  if [ -n "${WATCHDOG_PID:-}" ]; then
    kill "$WATCHDOG_PID" 2>/dev/null || true
    WATCHDOG_PID=""
  fi
  return 0
}

# One attempt with the status kept, because "the server answered with an error"
# and "the server could not be reached" are different answers and the manifest
# needs the difference: `curl -f` reports the first as 22 and wget as 8, and a
# release that publishes no manifest says exactly that. `DOWNLOAD_STATUS` is 0
# when the attempt worked, 2 for an answer, 1 for anything else.
DOWNLOAD_STATUS=0
# The tool's own exit code, before it is folded into the three answers below.
DOWNLOAD_EXIT=0
try_download() {
  DOWNLOAD_STATUS=0
  DOWNLOAD_EXIT=0
  run_downloader "$@" || DOWNLOAD_EXIT=$?
  DOWNLOAD_STATUS="$DOWNLOAD_EXIT"
  if [ "$DOWNLOAD_STATUS" -eq 0 ]; then
    return 0
  fi
  if [ "$DOWNLOAD_STATUS" -eq 22 ] || [ "$DOWNLOAD_STATUS" -eq 8 ]; then
    DOWNLOAD_STATUS=2
  else
    DOWNLOAD_STATUS=1
  fi
  return 1
}

# Every downloader is tried by running it, never by asking `command -v`: BusyBox
# hush — the shell Padavan and several other stock firmwares give root — has no
# `command` builtin, so a PATH test reports a working wget as absent and the
# install stops before it tries a single mirror. Both are attempted because
# neither is guaranteed to work: a stock firmware may have only a wget, a box
# with Entware may have only a curl, and either may be built without TLS.
#
# 0 — the file is there, 2 — the source answered with an HTTP error, 1 — it did
# not answer. The binary's callers only ask whether it worked; the manifest's
# reads the difference (`fetch_manifest`).
download_file() {
  _url="$1"
  _dest="$2"
  # Seconds for one attempt, the binary's unless the caller says otherwise.
  _max="${3:-120}"
  # The watchdog's budget for this attempt: the tool's own flags are expected to
  # end it sooner, and the slack is for starting the tool and closing the file.
  DOWNLOAD_BUDGET=$((_max + 3))
  rm -f "$_dest" 2>/dev/null || true

  # curl: --connect-timeout/--max-time are understood by every curl; the second
  # attempt drops the certificate check for boxes with no CA bundle, and is
  # skipped when the first one was answered — a server that answered does not
  # need to be asked again without the certificate check.
  try_download curl -fsSL --connect-timeout 4 --max-time "$_max" "$_url" -o "$_dest" 2>/dev/null && [ -s "$_dest" ] && return 0
  [ "$DOWNLOAD_STATUS" -eq 2 ] && return 2
  # curl's own status says which failure this was, and one of them makes the
  # attempts left pointless. 6 is a name that does not resolve and 7 is a
  # connection that is refused or goes nowhere: the same address through the same
  # network, one tool later, gives the same answer — and on a network that
  # filters GitHub that is the answer every source gives, so paying it four times
  # per source is the difference between a failure in seconds and one in minutes.
  # 28 is the budget running out, the one case where the next tool can still
  # differ: curl -k has the same 4 s to connect and the same TLS stack, so it is
  # skipped as well, while wget has its own budget and gets its turn.
  case "$DOWNLOAD_EXIT" in
    6|7) return 1 ;;
  esac
  if [ "$DOWNLOAD_EXIT" != "28" ]; then
    try_download curl -kfsSL --connect-timeout 4 --max-time "$_max" "$_url" -o "$_dest" 2>/dev/null && [ -s "$_dest" ] && return 0
    [ "$DOWNLOAD_STATUS" -eq 2 ] && return 2
  fi

  # wget: BusyBox knows neither `--timeout` nor `--no-check-certificate`, so the
  # first form is for GNU wget and `-T`, which both understand, is the second.
  # GNU wget's `--timeout` is every phase at once; the two flags are that split
  # in two, so a source that drops the packets costs the 4 s curl already paid
  # rather than the whole download budget again, while the read budget stays
  # `$_max` for a slow line. `--tries=1` is what makes it one attempt: GNU wget
  # retries twenty times by default, and against a dropped address that measured
  # 442 s and counting rather than the 120 s the flag promises. BusyBox wget has
  # none of these options — its `-T` is the read timeout, and on that same
  # address its connect phase took 132 s whatever the flag said, which is what
  # the watchdog in `run_downloader` is there to cut short.
  # There is no third, optionless form on purpose: it would be the one attempt
  # with no timeout at all — BusyBox has none and GNU wget waits 900 s for a
  # first byte — so a source that accepts the connection and then trickles would
  # hold the install past the budget every other attempt respects, and it would
  # be reached exactly when the bounded attempts timed out, i.e. on that source.
  try_download wget -q --connect-timeout=4 --read-timeout="$_max" --tries=1 -O "$_dest" "$_url" 2>/dev/null && [ -s "$_dest" ] && return 0
  [ "$DOWNLOAD_STATUS" -eq 2 ] && return 2
  # GNU wget's own status says whether the second form deserves its turn: 4 is a
  # network failure and 5 an SSL verification failure, and the second form is the
  # same tool at the same address with a wider timeout and no certificate flag
  # between them, so it can only repeat the answer — at up to 120 s per retry.
  # BusyBox wget exits 1 for everything, unknown options included, and that is
  # the case this form exists for: it gets its turn.
  case "$DOWNLOAD_EXIT" in
    4|5) return 1 ;;
  esac
  try_download wget -q -T "$_max" -O "$_dest" "$_url" 2>/dev/null && [ -s "$_dest" ] && return 0
  [ "$DOWNLOAD_STATUS" -eq 2 ] && return 2

  # Say why when the reason is that neither tool is installed at all.
  if ! curl --version >/dev/null 2>&1 && ! wget --help >/dev/null 2>&1; then
    echo "Error: neither curl nor wget found in PATH." >&2
  fi
  return 1
}

# The asset's URL on GitHub itself: the release the manifest is checked against,
# and the head of the list below. `DPI_RELEASE_BASE` replaces the
# `https://github.com/<repo>/releases` prefix for a source that mirrors the same
# layout — CI points it at a local fixture, which is the only way the manifest
# lookup below can be exercised: it asks the canonical release first and treats
# its answer as final, so a fixture reachable only through `DPI_MIRRORS` is never
# asked for the manifest.
release_url() {
  _base="${DPI_RELEASE_BASE:-https://github.com/${REPO}/releases}"
  _base="${_base%/}"
  if [ "$VERSION" = "latest" ]; then
    echo "${_base}/latest/download/$1"
  else
    echo "${_base}/download/${VERSION}/$1"
  fi
}

# Where the manifest of a release sits, given the URL of one of its assets: the
# asset name is the last path segment in every source's URL — the release URL and
# the proxies that wrap it alike — so the directory is what stays.
manifest_url() {
  echo "${1%/*}/SHA256SUMS.txt"
}

# Every release asset this script fetches — the binary and `SHA256SUMS.txt` —
# is looked for at the same set of sources, so the list is built from the asset
# name rather than written twice.
build_url_list() {
  _file="$1"
  _list=""
  if [ -n "${DPI_MIRRORS:-}" ]; then
    for _m in $DPI_MIRRORS; do
      _list="${_list} ${_m%/}/${_file}"
    done
  fi

  _gh=$(release_url "$_file")

  _list="${_list} ${_gh}"
  _list="${_list} https://ghfast.top/${_gh}"
  _list="${_list} https://ghproxy.net/${_gh}"
  _list="${_list} https://gh-proxy.com/${_gh}"
  _list="${_list} https://ghproxy.vip/${_gh}"
  _list="${_list} https://gh-proxy.org/${_gh}"
  _list="${_list} https://github.boki.moe/${_gh}"
  echo "$_list"
}

# The manifest is fetched once: from the release itself, and then from the source
# the binary came from when the release cannot be reached.
#
# The release URL is what the check is against — it is the published build — and
# its answer settles whether a manifest exists at all: a mirror only has what the
# release has, so an HTTP error there ends the search instead of sending the
# install through the other sources. That is what the sweep of every source this
# used to do got wrong: a release from before the manifest existed answers 404 on
# all of them, and through the proxies that is seconds per source rather than
# nothing — measured 31 s of silence *after* the binary was already on disk — and
# a source that stalls instead of answering costs its whole budget, one at a time.
# The source the binary came from is asked only when GitHub itself did not answer,
# which is the case this script exists for on a filtered network.
fetch_manifest() {
  [ -z "$MANIFEST_STATE" ] || return 0
  _canonical=$(release_url "SHA256SUMS.txt")
  _near=""
  if [ -n "$FETCHED_URL" ]; then
    _near=$(manifest_url "$FETCHED_URL")
  fi
  _seen=""
  for _url in "$_canonical" "$_near"; do
    if [ -z "$_url" ]; then
      continue
    fi
    if [ "$_url" = "$_seen" ]; then
      continue
    fi
    _seen="$_url"
    _rc=0
    download_file "$_url" "$MANIFEST_FILE" "$MANIFEST_MAX_TIME" || _rc=$?
    if [ "$_rc" -eq 0 ] && [ -s "$MANIFEST_FILE" ]; then
      MANIFEST_STATE="ok"
      return 0
    fi
    if [ "$_rc" -eq 2 ]; then
      break
    fi
  done
  rm -f "$MANIFEST_FILE" 2>/dev/null || true
  MANIFEST_STATE="missing"
  return 1
}

# The hash of a file, from whichever tool the box happens to have. Tried by
# running them, for the same reason the downloaders are: BusyBox hush has no
# `command` builtin, so a PATH test reports a tool that works as absent.
# `openssl dgst` prints `SHA2-256(file)= <hash>` and `sha256sum` prints
# `<hash>  <file>`, so the hash is the first field in one and the last in the
# other. No output means neither tool exists.
file_sha256() {
  _out=$(sha256sum "$1" 2>/dev/null | awk '{ print $1; exit }')
  [ -n "$_out" ] && { echo "$_out"; return 0; }
  _out=$(openssl dgst -sha256 "$1" 2>/dev/null | awk '{ print $NF; exit }')
  [ -n "$_out" ] && { echo "$_out"; return 0; }
  return 1
}

# Said once, not once per mirror: a release without a manifest, or a box without
# a hashing tool, would otherwise repeat the same warning for all eight sources.
checksum_note() {
  [ -z "${CHECKSUM_NOTE_SHOWN:-}" ] || return 0
  CHECKSUM_NOTE_SHOWN="1"
  echo "Warning: $1" >&2
}

# 0 — the candidate matches the manifest, or there is nothing to match it
#     against (no manifest, no entry, no hashing tool): the install proceeds.
# 1 — it does not match. The caller drops the file and tries the next source,
#     exactly as it does for a download that failed.
verify_checksum() {
  _name="$1"
  if [ -z "$MANIFEST_STATE" ]; then
    fetch_manifest || true
  fi
  if [ "$MANIFEST_STATE" != "ok" ]; then
    checksum_note "this release has no SHA256SUMS.txt; installing without a checksum check."
    return 0
  fi
  # `$NF` covers both `hash  name` and `hash *name`; the name is compared whole,
  # so a target that is a prefix of another cannot match the wrong line.
  _want=$(awk -v name="$_name" '{ n = $NF; if (substr(n, 1, 1) == "*") n = substr(n, 2); if (n == name) { print $1; exit } }' "$MANIFEST_FILE" 2>/dev/null)
  if [ -z "$_want" ]; then
    checksum_note "$_name is not listed in SHA256SUMS.txt; installing without a checksum check."
    return 0
  fi
  if ! _have=$(file_sha256 "$TMP_FILE"); then
    checksum_note "neither sha256sum nor openssl is available; installing without a checksum check."
    return 0
  fi
  if [ "$_have" = "$_want" ]; then
    CHECKSUM_RESULT="verified"
    echo "Checksum verified: ${_have}"
    return 0
  fi
  echo "Warning: $_name does not match the published checksum (expected ${_want}, got ${_have})." >&2
  return 1
}

# Every mirror is started at once and the first download that finishes wins; the
# others are stopped, download and all — the worker is a subshell and the tool it
# started is its child, so killing the worker alone would leave the download
# running to its own `--max-time` (the worker's trap is what stops it). This is
# about the one bad case the sequential loop cannot escape: a mirror that accepts
# the connection and then trickles, which costs the whole `--max-time` before the
# next one is tried. The race picks the fast mirror whatever the order, and what
# it produces is still only a *candidate* — the caller runs it (`--version`)
# exactly as in the sequential path, and a candidate that fails sends every
# mirror down that path in turn.
#
# The race costs disk, not just traffic: every mirror writes its own copy into the
# install directory at the same time, so it only runs when that directory can hold
# one copy per mirror with room to spare — `mirrors × RACE_MIRROR_KB` against
# `RACE_MIN_KB` as the floor, whichever is larger. When the space is not there (or
# `df` cannot say), the mirrors are tried one by one and the install still
# completes; it may just be slower when a mirror trickles.
RACE_MIN_KB=30720        # 30 MB floor, enough for the shipped router targets
RACE_MIRROR_KB=5120      # per-mirror share: the standard MIPS build is ~4.6 MB
#
# Completion is recorded as a file per mirror rather than by watching processes:
# a finished background child stays a zombie that `kill -0` still reports as
# alive, and the loop has to end when the last mirror is done, successful or not.
race_download() {
  _tgt="$1"
  _urls=$(build_url_list "$_tgt")
  _n=0
  for _url in $_urls; do
    _n=$((_n + 1))
  done

  _need=$((_n * RACE_MIRROR_KB))
  [ "$_need" -ge "$RACE_MIN_KB" ] || _need="$RACE_MIN_KB"
  _avail=$(get_avail_kb "$OUT_DIR")
  if [ -z "$_avail" ] || [ "$_avail" -lt "$_need" ]; then
    _have="unknown"
    [ -n "$_avail" ] && _have="$((_avail / 1024)) MB"
    echo "Notice: not enough free space in ${OUT_DIR} for ${_n} copies at once (need ~$((_need / 1024)) MB, have ${_have})."
    echo "        Trying the mirrors one by one."
    return 1
  fi

  RACE_DIR="${OUT_DIR}/.dpi-race.$$"
  rm -rf "$RACE_DIR" 2>/dev/null
  mkdir -p "$RACE_DIR" 2>/dev/null || {
    RACE_DIR=""
    return 1
  }

  RACE_PIDS=""
  _i=0
  for _url in $_urls; do
    _i=$((_i + 1))
    _part="${RACE_DIR}/part.${_i}"
    _flag="${RACE_DIR}/flag.${_i}"
    _done="${RACE_DIR}/done.${_i}"
    (
      # A stopped worker has to stop its own download: the signal reaches this
      # subshell, not the curl/wget it is waiting for (see `run_downloader`).
      trap 'stop_downloader; exit 0' INT TERM HUP
      if download_file "$_url" "$_part" && [ -s "$_part" ]; then
        printf '%s\n' "$_url" > "$_flag"
      fi
      : > "$_done"
    ) &
    RACE_PIDS="${RACE_PIDS} $!"
  done
  echo "Racing ${_n} mirrors for ${_tgt}..."

  _winner=""
  while [ -z "$_winner" ]; do
    _i=0
    _pending=""
    while [ "$_i" -lt "$_n" ]; do
      _i=$((_i + 1))
      if [ -s "${RACE_DIR}/flag.${_i}" ]; then
        [ -n "$_winner" ] || _winner="$_i"
      elif [ ! -e "${RACE_DIR}/done.${_i}" ]; then
        _pending="yes"
      fi
    done
    [ -n "$_winner" ] && break
    [ -n "$_pending" ] || break
    sleep 1
  done

  # `kill` fails on a PID that is already gone, and under `set -e` that would
  # abort the install *after* the winner was downloaded — `stop_workers` owns the
  # `|| true`, and the same call is what the interrupt handler makes.
  stop_workers

  if [ -z "$_winner" ]; then
    rm -rf "$RACE_DIR" 2>/dev/null
    RACE_DIR=""
    return 1
  fi

  FETCHED_URL=$(cat "${RACE_DIR}/flag.${_winner}")
  echo "Fetched from: ${FETCHED_URL}"
  if mv -f "${RACE_DIR}/part.${_winner}" "$TMP_FILE" 2>/dev/null; then
    rm -rf "$RACE_DIR" 2>/dev/null
    RACE_DIR=""
    return 0
  fi
  rm -f "$TMP_FILE" 2>/dev/null
  rm -rf "$RACE_DIR" 2>/dev/null
  RACE_DIR=""
  return 1
}

# A mirror is accepted only when the file it served both downloaded and ran:
# `--version` is executed, not stat'ed. The compact builds are UPX-packed, and a
# packer's unpacking stub can be unusable on a given kernel even though the file
# is intact — UPX 5.x needs `memfd_create`, i.e. Linux >= 3.17, and dies with
# `Trace/breakpoint trap` on the 3.4 kernels several router firmwares ship (see
# the UPX pin in `.github/workflows/release.yml`). Such a file counts as a failed
# mirror, and the standard build gets its turn.
try_download_and_verify() {
  _tgt="$1"
  echo "Downloading ${_tgt} (${VERSION}) to ${OUT_FILE}..."

  if race_download "$_tgt"; then
    if verify_checksum "$_tgt"; then
      chmod +x "$TMP_FILE"
      if _ver=$("$TMP_FILE" --version 2>&1); then
        echo "Verified: ${_ver}"
        return 0
      fi
      echo "Warning: the first mirror's binary failed architecture/runtime check, trying the rest one by one..." >&2
    fi
    rm -f "$TMP_FILE" 2>/dev/null || true
  fi

  _urls=$(build_url_list "$_tgt")
  for _url in $_urls; do
    echo "Fetching from: ${_url} ..."
    # What `fetch_manifest` looks beside when this candidate is checked: the
    # manifest is looked for next to the file it describes.
    FETCHED_URL="$_url"
    rm -f "$TMP_FILE" 2>/dev/null || true
    if download_file "$_url" "$TMP_FILE" && [ -s "$TMP_FILE" ]; then
      if ! verify_checksum "$_tgt"; then
        rm -f "$TMP_FILE" 2>/dev/null || true
        continue
      fi
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

# The version an installed binary reports, "" when it cannot be run or says
# nothing. `VERSION` is written with its `v` (`v5.0.0-alpha.19`) and the binary
# prints without it (`dpi-detector 5.0.0-alpha.19`), so the `v` is dropped on the
# way out and what is compared is plain text. The version flag is `--version`
# (`-V`); `-v` is the detector's `--verbose`.
binary_version() {
  _out=$("$1" --version 2>/dev/null) || return 0
  _last=""
  for _word in $_out; do
    _last="$_word"
  done
  printf '%s\n' "${_last#v}"
}

# A destination that already holds this release is not downloaded again: the
# reason to run the installer a second time is to run the tester, and the file
# that is there is the one it would have fetched. `-x` comes first — a file that
# cannot be run is not a version, which is also how a binary built for another
# architecture is passed over — and a moving `latest` tag is left out, because
# there is no fixed string to compare the file's own report against.
LOCAL_VERSION=""
LOCAL_CURRENT=0
if [ -x "$OUT_FILE" ]; then
  LOCAL_VERSION=$(binary_version "$OUT_FILE")
fi
if [ -n "$LOCAL_VERSION" ]; then
  if [ "$VERSION" != "latest" ] && [ "$LOCAL_VERSION" = "${VERSION#v}" ]; then
    LOCAL_CURRENT=1
    echo "Already installed: dpi-detector ${LOCAL_VERSION} at ${OUT_FILE} — nothing to download."
  elif [ "$VERSION" != "latest" ]; then
    echo "Installed: dpi-detector ${LOCAL_VERSION}, this installer carries ${VERSION#v} — installing that release."
  fi
fi

if [ "$LOCAL_CURRENT" -eq 0 ]; then
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
  # What the file really occupies, measured after it is in place — not the size the
  # release notes promise. `du` counts allocated blocks (what `df` will report as
  # used); when it is unavailable, the apparent size rounded up to a block does.
  SIZE_KB=$(du -k "$OUT_FILE" 2>/dev/null | awk 'NR == 1 { print $1 + 0 }')
  [ -n "$SIZE_KB" ] && [ "$SIZE_KB" -gt 0 ] || SIZE_KB=$(( ($(wc -c < "$OUT_FILE") + 1023) / 1024 ))
  SIZE_MB=$(awk -v kb="$SIZE_KB" 'BEGIN { printf "%.1f", kb / 1024 }' 2>/dev/null)
  [ -n "$SIZE_MB" ] || SIZE_MB=$((SIZE_KB / 1024))
fi
RUN_FILE="$OUT_FILE"

# The command to suggest: the bare name when the shell would reach this very file
# by walking PATH — then `dpi-detector` is what the user types — and the full path
# otherwise, including when PATH resolves the name to a *different* dpi-detector,
# because then the bare name would start something else. `command -v` is not an
# option here for the same reason the downloaders are tried by running them:
# BusyBox hush has no `command` builtin.
CMD_RUN="$RUN_FILE"
_resolved=""
_old_ifs="$IFS"
IFS=:
for _dir in $PATH; do
  [ -n "$_dir" ] || _dir="."
  _candidate="${_dir%/}/dpi-detector"
  if [ -x "$_candidate" ]; then
    _resolved="$_candidate"
    break
  fi
done
IFS="$_old_ifs"
if [ "$_resolved" = "$RUN_FILE" ]; then
  CMD_RUN="dpi-detector"
fi

echo ""
echo "=============================================="
if [ "$LOCAL_CURRENT" -eq 1 ]; then
  echo "  DPI Detector is already installed!"
  echo "  Location: ${RUN_FILE}"
  echo "  Version:  ${LOCAL_VERSION} — the release this installer carries"
else
  echo "  DPI Detector successfully installed!"
  echo "  Location: ${RUN_FILE}"
  case "$CHOSEN_TARGET" in
    *-upx)
      echo "  Variant:  Compact UPX (${SIZE_MB} MB)"
      ;;
    *)
      echo "  Variant:  Standard (${SIZE_MB} MB)"
      ;;
  esac
  echo "  Checksum: ${CHECKSUM_RESULT}"
fi
echo "=============================================="
echo ""
echo "To start the interactive menu:"
echo "  ${CMD_RUN}"
echo ""
echo "For help:"
echo "  ${CMD_RUN} --help"
echo ""

# Only run automatically if user explicitly passed arguments (e.g. sh -s -- -t 1)
if [ $# -gt 0 ]; then
  exec "$RUN_FILE" "$@"
fi
}

main "$@"
