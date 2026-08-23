#!/bin/sh
# Netherchat installer — installs the `netherchat` terminal client.
#
#   curl -fsSL https://netherchat.com/install | bash
#   curl -fsSL https://netherchat.com/install | bash -s -- --with-server
#
# The unpinned form installs the latest release; pass --version to pin one, and
# --with-server to also install the relay. See Options below.
#
# Netherchat is two artifacts: the endpoint client (installed by default) and the
# netherchat-server relay. --with-server also installs the relay binary, which
# already ships in the same release archive. POSIX sh — no bashisms — so it runs
# under sh, bash, ash (Alpine) and zsh alike.
#
# Every download is checked against the release's published SHA-256 before
# anything is written to your PATH, and a download that cannot be checked is NOT
# installed. See --allow-unverified below, and docs/verifying-downloads.md for
# what a checksum does and does not prove.
#
# Options:
#   --version <v>       install a specific version (default: latest release)
#   --bin-dir <dir>     install into <dir> (default: ~/.local/bin)
#   --with-server       also install the netherchat-server relay binary
#   --allow-unverified  install even if the checksum cannot be OBTAINED. Never
#                       skips a checksum that is present and wrong. Type it to
#                       mean it — there is no environment variable for this.
#   --uninstall         remove the installed client (and relay, if present)
#   -h, --help          show this help
#
# Honored env vars: NETHERCHAT_VERSION, NETHERCHAT_BIN_DIR, NO_COLOR.

set -eu

REPO="astralis-software-systems/netherchat"
BINARY="netherchat"
SERVER_BINARY="netherchat-server"
VERSION="${NETHERCHAT_VERSION:-latest}"
BIN_DIR="${NETHERCHAT_BIN_DIR:-}"
DO_UNINSTALL=0
DO_SERVER=0
# Deliberately NOT read from the environment. This is the one decision in the
# script that trades away a security property, so it has to be typed on the
# command line where the person running it can see it.
ALLOW_UNVERIFIED=0

# ---- pretty output ----------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RST=$(printf '\033[0m'); C_DIM=$(printf '\033[2m')
  C_GRN=$(printf '\033[32m'); C_YEL=$(printf '\033[33m')
  C_RED=$(printf '\033[31m'); C_VIO=$(printf '\033[35m')
else
  C_RST=''; C_DIM=''; C_GRN=''; C_YEL=''; C_RED=''; C_VIO=''
fi
step() { printf '%s›%s %s\n' "$C_VIO" "$C_RST" "$1"; }
ok()   { printf '  %s✓%s %s\n' "$C_GRN" "$C_RST" "$1"; }
warn() { printf '  %s!%s %s\n' "$C_YEL" "$C_RST" "$1" >&2; }
die()  { printf '%serror:%s %s\n' "$C_RED" "$C_RST" "$1" >&2; exit 1; }

# Prints the header comment block. Reads it structurally rather than by line
# number: the previous `sed -n '2,19p'` silently truncated its own help text the
# moment a line was added above the Options list.
usage() {
  awk 'NR==1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0" 2>/dev/null || true
}

# ---- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --bin-dir)   [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift 2 ;;
    --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
    --with-server) DO_SERVER=1; shift ;;
    --allow-unverified) ALLOW_UNVERIFIED=1; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

# ---- helpers ----------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL -> stdout ; download URL FILE -> file
if have curl; then
  fetch()    { curl -fsSL "$1"; }
  download() { curl -fsSL -o "$2" "$1"; }
elif have wget; then
  fetch()    { wget -qO- "$1"; }
  download() { wget -qO "$2" "$1"; }
else
  die "need curl or wget to download Netherchat"
fi

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum;  then shasum -a 256 "$1" | awk '{print $1}'
  else return 1
  fi
}

detect_bin_dir() {
  if [ -n "$BIN_DIR" ]; then return; fi
  BIN_DIR="$HOME/.local/bin"
}

# ---- uninstall --------------------------------------------------------------
if [ "$DO_UNINSTALL" -eq 1 ]; then
  detect_bin_dir
  target="$BIN_DIR/$BINARY"
  if [ -e "$target" ]; then
    rm -f "$target" && ok "removed $target"
  else
    warn "no $BINARY found in $BIN_DIR — nothing to do"
  fi
  server_target="$BIN_DIR/$SERVER_BINARY"
  if [ -e "$server_target" ]; then
    rm -f "$server_target" && ok "removed $server_target"
  fi
  exit 0
fi

# ---- platform ---------------------------------------------------------------
step "Detecting platform"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported OS '$os' — Netherchat supports Linux and macOS here; on Windows run installer/install.ps1" ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'" ;;
esac
ok "$os/$arch"

# ---- resolve version --------------------------------------------------------
step "Resolving release"
if [ "$VERSION" = "latest" ]; then
  tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 \
        | sed -e 's/.*"tag_name":[[:space:]]*"//' -e 's/".*//')
  [ -n "$tag" ] || die "could not resolve the latest release (is the repo published yet?)"
else
  tag="v${VERSION#v}"
fi
ver="${tag#v}"
ok "netherchat $ver"

# ---- download + verify ------------------------------------------------------
archive="${BINARY}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t netherchat)
trap 'rm -rf "$tmp"' EXIT INT TERM

step "Downloading $archive"
download "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
ok "downloaded"

# ---- verify -----------------------------------------------------------------
# FAIL CLOSED. Three of the four outcomes below used to warn and carry on, which
# meant an installer for a security product would put an unverified executable on
# a user's PATH whenever the release page was slow, partial, or hostile — and say
# so in yellow, once, in a stream of green ticks nobody reads.
#
# The distinction that matters: a checksum that is PRESENT AND WRONG is evidence
# of a problem and is always fatal, --allow-unverified or not. A checksum that
# cannot be obtained is an absence of evidence, and that is the only thing
# --allow-unverified lets you accept.
step "Verifying checksum"
verified=0
reason=""
if download "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
  actual=$(sha256_of "$tmp/$archive" || true)
  expected=$(grep " ${archive}\$" "$tmp/checksums.txt" | awk '{print $1}' | head -1 || true)
  if [ -z "$actual" ]; then
    reason="this system has neither sha256sum nor shasum"
  elif [ -z "$expected" ]; then
    reason="release $tag publishes no checksum for $archive"
  elif [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $archive (expected $expected, got $actual) — NOT installing"
  else
    verified=1
  fi
else
  reason="could not fetch $base/checksums.txt"
fi

if [ "$verified" -eq 1 ]; then
  ok "sha256 verified"
elif [ "$ALLOW_UNVERIFIED" -eq 1 ]; then
  warn "INSTALLING AN UNVERIFIED DOWNLOAD — $reason"
  warn "--allow-unverified was given, so this is proceeding without checking the bytes."
else
  die "cannot verify $archive: $reason.
       Refusing to install an executable whose integrity was not checked.
       Re-run with --allow-unverified to accept that deliberately, or fetch the
       release by hand from https://github.com/$REPO/releases/tag/$tag and check
       it yourself. See docs/verifying-downloads.md."
fi

# ---- extract + install ------------------------------------------------------
step "Installing"
tar -xzf "$tmp/$archive" -C "$tmp" || die "failed to extract $archive"
[ -f "$tmp/$BINARY" ] || die "archive did not contain a '$BINARY' binary"

detect_bin_dir
mkdir -p "$BIN_DIR" 2>/dev/null || die "cannot create $BIN_DIR"
if ! cp "$tmp/$BINARY" "$BIN_DIR/$BINARY" 2>/dev/null; then
  die "cannot write to $BIN_DIR — re-run with --bin-dir <writable dir>"
fi
chmod 0755 "$BIN_DIR/$BINARY"
ok "installed to $BIN_DIR/$BINARY"

# Opt-in relay: the server binary already rode down inside this same archive, so
# --with-server installs it with zero extra download. If it is absent (an older
# release), warn and continue — the client install must always succeed.
if [ "$DO_SERVER" -eq 1 ]; then
  if [ -f "$tmp/$SERVER_BINARY" ]; then
    if cp "$tmp/$SERVER_BINARY" "$BIN_DIR/$SERVER_BINARY" 2>/dev/null; then
      chmod 0755 "$BIN_DIR/$SERVER_BINARY"
      ok "installed to $BIN_DIR/$SERVER_BINARY"
    else
      warn "cannot write $SERVER_BINARY to $BIN_DIR — relay not installed (the client is fine)"
    fi
  else
    warn "this release has no $SERVER_BINARY — relay not installed (the client is fine); get it via Docker or 'go build ./cmd/netherchat-server' — see docs/self-hosting.md"
  fi
fi

# ---- PATH hint + next steps -------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH"
    printf '    add this to your shell profile:\n      %sexport PATH="%s:$PATH"%s\n' "$C_DIM" "$BIN_DIR" "$C_RST"
    ;;
esac

if [ "$DO_SERVER" -eq 1 ]; then
  printf '\n%sNetherchat %s installed — client + relay.%s  Messaging that lives below the surface.\n' "$C_VIO" "$ver" "$C_RST"
  printf '  %sConnect:%s     netherchat connect ws://localhost:3000 --name "$USER"\n' "$C_DIM" "$C_RST"
  printf '  %sRun a relay:%s netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)\n' "$C_DIM" "$C_RST"
  printf '  %sUninstall:%s   curl -fsSL https://netherchat.com/install | bash -s -- --uninstall\n\n' "$C_DIM" "$C_RST"
else
  printf '\n%sNetherchat %s installed — the endpoint client.%s  Messaging that lives below the surface.\n' "$C_VIO" "$ver" "$C_RST"
  printf '  %sConnect:%s    netherchat connect ws://localhost:3000 --name "$USER"\n' "$C_DIM" "$C_RST"
  printf '  %sSelf-host:%s  re-run with --with-server for the native relay (netherchat-server — already in\n' "$C_DIM" "$C_RST"
  printf '              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat\n'
  printf '  %sUninstall:%s  curl -fsSL https://netherchat.com/install | bash -s -- --uninstall\n\n' "$C_DIM" "$C_RST"
fi
