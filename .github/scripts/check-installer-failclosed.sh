#!/usr/bin/env bash
#
# check-installer-failclosed.sh — run installer/install.sh end to end against a
# local release and prove it refuses to install a binary it could not verify.
#
# WHY IT RUNS THE INSTALLER INSTEAD OF READING IT. The property under test is
# "what happens to a user when the checksum is unavailable", and that is a
# runtime property of a script with four separate exits from its verification
# block. Reading the source tells you which branch you think fires; running it
# tells you which one does. So this starts where a user starts: `sh install.sh`,
# a release it downloads over HTTP, and a check of whether a binary ended up on
# disk.
#
# It does not add a URL override to install.sh. A download-location knob on a
# security installer is a knob an attacker can turn, and a test is not a reason
# to ship one. Instead it copies install.sh, rewrites the one line that builds
# the release URL, and asserts the rewrite matched — so if that line is ever
# renamed, this fails loudly rather than testing a stale copy.
#
# Cases:
#   A  correct checksums.txt          -> installs, says "sha256 verified"
#   B  checksums.txt 404              -> REFUSES, installs nothing
#   C  checksums.txt with no entry    -> REFUSES, installs nothing
#   D  checksum mismatch              -> REFUSES, installs nothing
#   E  no sha256 tool on PATH         -> REFUSES, installs nothing
#   E' same restricted PATH, tool back-> installs   (proves E failed for the
#                                        stated reason and not because the
#                                        restricted PATH broke the installer)
#   F  --allow-unverified + case B    -> installs, and says so loudly
#
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2

SRC="installer/install.sh"
[ -f "$SRC" ] || { echo "::error::$SRC not found"; exit 1; }

work=$(mktemp -d)
# shellcheck disable=SC2064
trap "kill %1 2>/dev/null; rm -rf '$work'" EXIT INT TERM

serve="$work/serve"
mkdir -p "$serve"

# ---- the installer under test, pointed at a local release --------------------
sut="$work/install-under-test.sh"
sed 's#^base="https://github.com/\$REPO/releases/download/\$tag"$#base="$NC_TEST_BASE"#' "$SRC" > "$sut"
if ! grep -q '^base="\$NC_TEST_BASE"$' "$sut"; then
    echo "::error::could not find the release-URL line in $SRC — this test is reading a shape that no longer exists"
    grep -n 'releases/download' "$SRC" >&2 || true
    exit 1
fi

# ---- a fake release ----------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
archive="netherchat_${os}_${arch}.tar.gz"

payload="$work/payload"
mkdir -p "$payload"
printf '#!/bin/sh\necho netherchat-fake\n' > "$payload/netherchat"
printf '#!/bin/sh\necho netherchat-server-fake\n' > "$payload/netherchat-server"
chmod 0755 "$payload/netherchat" "$payload/netherchat-server"
tar -czf "$serve/$archive" -C "$payload" netherchat netherchat-server
good_sum=$(sha256sum "$serve/$archive" | awk '{print $1}')

port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
( cd "$serve" && python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 ) &
for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/$archive" 2>/dev/null && break
    sleep 0.1
done

export NC_TEST_BASE="http://127.0.0.1:$port"

fails=0
LAST_RC=0
LAST_INSTALLED=no
report() {
    if [ "$1" = "ok" ]; then printf '  ok    %s\n' "$2"
    else printf '::error::%s\n' "$2" >&2; fails=$((fails + 1)); fi
}

# run <case> <expect: install|refuse> <extra args...>
run_case() {
    label="$1"; expect="$2"; shift 2
    bindir="$work/bin-$label"
    rm -rf "$bindir"
    out="$work/out-$label.txt"
    set +e
    ( sh "$sut" --version 9.9.9 --bin-dir "$bindir" "$@" ) >"$out" 2>&1
    rc=$?
    set -e
    installed=no; [ -f "$bindir/netherchat" ] && installed=yes
    LAST_RC=$rc; LAST_INSTALLED=$installed

    case "$expect" in
    install)
        if [ "$rc" -eq 0 ] && [ "$installed" = yes ]; then
            report ok "$label: installed (rc=0)"
        else
            report bad "$label: expected a successful install, got rc=$rc installed=$installed"
            sed 's/^/        /' "$out" >&2
        fi
        ;;
    refuse)
        if [ "$rc" -ne 0 ] && [ "$installed" = no ]; then
            report ok "$label: refused (rc=$rc, nothing installed)"
        else
            report bad "$label: expected a refusal, got rc=$rc installed=$installed"
            sed 's/^/        /' "$out" >&2
        fi
        ;;
    esac
}

echo "installer fail-closed (install.sh):"

# A — the happy path.
printf '%s  %s\n' "$good_sum" "$archive" > "$serve/checksums.txt"
run_case A-verified install
if [ "$LAST_RC" -eq 0 ] && [ "$LAST_INSTALLED" = yes ] && grep -q "sha256 verified" "$work/out-A-verified.txt"; then
    report ok "A-verified: printed 'sha256 verified'"
else
    report bad "A: did not install-and-verify"
fi

# B — checksums.txt is not there at all.
rm -f "$serve/checksums.txt"
run_case B-no-checksums-file refuse

# C — checksums.txt exists but says nothing about our archive.
printf '%s  %s\n' "$good_sum" "netherchat_someotherthing.tar.gz" > "$serve/checksums.txt"
run_case C-no-entry refuse

# D — the archive is not what the release says it is.
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$archive" \
    > "$serve/checksums.txt"
run_case D-mismatch refuse

# E — no sha256 tool. A restricted PATH holding everything install.sh needs
# EXCEPT sha256sum/shasum.
printf '%s  %s\n' "$good_sum" "$archive" > "$serve/checksums.txt"
stub="$work/stubbin"
mkdir -p "$stub"
for t in sh curl wget uname tr mktemp tar gzip gunzip mkdir cp chmod grep awk sed rm head cat sleep; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$stub/$t"
done
(
    export PATH="$stub"
    bindir="$work/bin-E-no-sha-tool"; rm -rf "$bindir"
    sh "$sut" --version 9.9.9 --bin-dir "$bindir" >"$work/out-E-no-sha-tool.txt" 2>&1
    echo $? > "$work/rc-E"
) || true
rc=$(cat "$work/rc-E" 2>/dev/null || echo 1)
if [ "$rc" -ne 0 ] && [ ! -f "$work/bin-E-no-sha-tool/netherchat" ]; then
    report ok "E-no-sha-tool: refused (rc=$rc, nothing installed)"
else
    report bad "E-no-sha-tool: expected a refusal, got rc=$rc installed=$([ -f "$work/bin-E-no-sha-tool/netherchat" ] && echo yes || echo no)"
    sed 's/^/        /' "$work/out-E-no-sha-tool.txt" >&2
fi

# E' — the same restricted PATH with sha256sum put back. If this does not
# install, E above proved nothing: the PATH would be what broke it.
p=$(command -v sha256sum) && ln -sf "$p" "$stub/sha256sum"
(
    export PATH="$stub"
    bindir="$work/bin-E2-control"; rm -rf "$bindir"
    sh "$sut" --version 9.9.9 --bin-dir "$bindir" >"$work/out-E2-control.txt" 2>&1
    echo $? > "$work/rc-E2"
) || true
rc=$(cat "$work/rc-E2" 2>/dev/null || echo 1)
if [ "$rc" -eq 0 ] && [ -f "$work/bin-E2-control/netherchat" ]; then
    report ok "E'-control: same PATH plus sha256sum installs — E failed for the right reason"
else
    report bad "E'-control: the restricted PATH itself breaks the installer, so case E proves nothing (rc=$rc)"
    sed 's/^/        /' "$work/out-E2-control.txt" >&2
fi
rm -f "$stub/sha256sum"

# F — the explicit opt-out. It must exist (an installer with no escape hatch
# gets forked), it must never be the default, and it must say what it did.
rm -f "$serve/checksums.txt"
run_case F-optout install --allow-unverified
if [ "$LAST_INSTALLED" = yes ] && grep -qiE 'UNVERIFIED DOWNLOAD' "$work/out-F-optout.txt"; then
    report ok "F-optout: warned about what it skipped"
else
    report bad "F-optout: did not install-and-warn (asserting on the text of a FAILED run is not evidence)"
fi

echo
if [ "$fails" -ne 0 ]; then
    printf '::error::installer fail-closed: %s check(s) failed\n' "$fails" >&2
    exit 1
fi
echo "installer fail-closed: all checks passed"
# EXIT EXPLICITLY, for the reason the .ps1 sibling does. A script's status is its
# last command's, and most cases here run the installer expecting a REFUSAL. This
# one happens to end on a case that expects an install, so it exits 0 by luck;
# reorder the cases and a green run reports failure. set -e does not cover this.
exit 0
