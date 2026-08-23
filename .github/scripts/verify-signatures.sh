#!/usr/bin/env bash
#
# verify-signatures.sh — assert that every Windows artifact about to ship is
# Authenticode-signed AND RFC 3161 timestamped, by reading the verifier's output
# rather than its exit code.
#
# WHY IT PARSES INSTEAD OF TRUSTING THE EXIT CODE. `osslsigncode verify` exits 0
# on a signature with no timestamp at all. Measured, not assumed:
#
#     $ osslsigncode sign -pkcs12 leaf.p12 ... -in nc.exe -out nots.exe   # no -ts
#     Succeeded
#     $ osslsigncode verify -CAfile ca.crt -in nots.exe
#     ...
#     Timestamp is not available
#     ...
#     Signature verification: ok
#     Succeeded
#     $ echo $?
#     0
#
# A verify step written as `osslsigncode verify … || exit 1` therefore passes an
# artifact that will stop verifying on customer machines about fifteen months
# after release, when the signing certificate expires. That is the whole class
# of defect this script exists to close, so it asserts on the text.
#
# WHY IT TAKES A DIRECTORY. The failure this guard is really for is not "the
# signer produced a bad signature" — it is "one artifact never reached the
# signer". A verify step handed an explicit file list can be green while an
# unsigned binary sits next to the ones it checked. Point this at the directory
# that is about to be archived; it enumerates every *.exe under it, and
# --expect-count fails if the set is the wrong size.
#
# Usage:
#   verify-signatures.sh --ca <ca.crt|system> [--expect-count N]
#                        [--expect-subject SUBSTR] [--tsa-ca <file>]
#                        <dir|file> [<dir|file> ...]
#
# Exit status: 0 only if every enumerated artifact passes every assertion.
#
set -euo pipefail

OSSLSIGNCODE="${OSSLSIGNCODE:-osslsigncode}"
CA=""
TSA_CA="${TSA_CA:-/etc/ssl/certs/ca-certificates.crt}"
EXPECT_COUNT=""
EXPECT_SUBJECT="${EXPECT_SUBJECT:-}"
targets=()

die() { printf 'verify-signatures: error: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
    --ca)             [ $# -ge 2 ] || die "--ca needs a value"; CA="$2"; shift 2 ;;
    --tsa-ca)         [ $# -ge 2 ] || die "--tsa-ca needs a value"; TSA_CA="$2"; shift 2 ;;
    --expect-count)   [ $# -ge 2 ] || die "--expect-count needs a value"; EXPECT_COUNT="$2"; shift 2 ;;
    --expect-subject) [ $# -ge 2 ] || die "--expect-subject needs a value"; EXPECT_SUBJECT="$2"; shift 2 ;;
    -h|--help)        sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)               die "unknown option: $1" ;;
    *)                targets+=("$1"); shift ;;
    esac
done

[ -n "$CA" ] || die "--ca is required (a CA bundle path, or the word 'system')"
[ "${#targets[@]}" -gt 0 ] || die "no files or directories given"
command -v "$OSSLSIGNCODE" >/dev/null 2>&1 || die "osslsigncode not found (set OSSLSIGNCODE)"

if [ "$CA" = "system" ]; then
    CA="/etc/ssl/certs/ca-certificates.crt"
fi
[ -f "$CA" ] || die "CA file not found: $CA"

# ---- enumerate ---------------------------------------------------------------
files=()
for t in "${targets[@]}"; do
    if [ -d "$t" ]; then
        while IFS= read -r line; do files+=("$line"); done < <(find "$t" -type f -name '*.exe' | sort)
    elif [ -f "$t" ]; then
        files+=("$t")
    else
        die "no such file or directory: $t"
    fi
done

if [ "${#files[@]}" -eq 0 ]; then
    die "no *.exe artifacts found under: ${targets[*]} — a verify step that checks nothing is a verify step that passes anything"
fi

if [ -n "$EXPECT_COUNT" ] && [ "${#files[@]}" -ne "$EXPECT_COUNT" ]; then
    printf 'verify-signatures: error: expected %s artifacts, found %s:\n' "$EXPECT_COUNT" "${#files[@]}" >&2
    printf '    %s\n' "${files[@]}" >&2
    exit 1
fi

printf 'verify-signatures: checking %s artifact(s) against CA %s\n' "${#files[@]}" "$CA"

fails=0
for f in "${files[@]}"; do
    name=$(basename "$f")
    out=$("$OSSLSIGNCODE" verify -CAfile "$CA" -TSA-CAfile "$TSA_CA" -in "$f" 2>&1) || true
    reasons=()

    # 1. There is a signature, and it verifies against the pinned trust anchor.
    grep -q '^Signature verification: ok' <<<"$out" || reasons+=("signature does not verify (or there is none)")

    # 2. Exactly one signature. Two would mean something re-signed the artifact
    #    after the signing job, which nothing in this pipeline is allowed to do.
    nsig=$(sed -n 's/^Number of verified signatures: //p' <<<"$out" | head -1)
    [ "$nsig" = "1" ] || reasons+=("expected exactly 1 verified signature, got '${nsig:-none}'")

    # 3. A timestamp exists. Both halves are asserted: the negative string that
    #    osslsigncode prints when there is none, and the positive string it
    #    prints only when the countersignature itself verified.
    grep -q 'Timestamp is not available' <<<"$out" && reasons+=("NOT TIMESTAMPED — the signature dies with the certificate")
    grep -q '^Timestamp Server Signature verification: ok' <<<"$out" || reasons+=("timestamp countersignature did not verify")

    # 4. SHA-256 or better. A SHA-1 Authenticode digest is rejected by every
    #    supported version of Windows and must never leave this pipeline.
    if grep -qE '^Message digest algorithm +: +(MD5|SHA1)\b' <<<"$out"; then
        reasons+=("weak message digest algorithm")
    fi
    grep -qE '^Message digest algorithm +: +SHA(256|384|512)\b' <<<"$out" || reasons+=("could not read a SHA-2 message digest algorithm")

    # 5. The signer is who we expect. Free before the certificate exists (the
    #    throwaway CN is checked); load-bearing after it, when --expect-subject
    #    is the Astralis organisation name on the real certificate.
    subject=$(sed -n 's/^\t\tSubject: //p' <<<"$out" | head -1)
    if [ -n "$EXPECT_SUBJECT" ] && [[ "$subject" != *"$EXPECT_SUBJECT"* ]]; then
        reasons+=("signer subject '$subject' does not contain '$EXPECT_SUBJECT'")
    fi

    tstime=$(sed -n 's/^\tTimestamp time: //p' <<<"$out" | head -1)

    if [ "${#reasons[@]}" -eq 0 ]; then
        printf '  PASS  %-28s  timestamped %s\n' "$name" "$tstime"
        printf '        signer: %s\n' "$subject"
    else
        fails=$((fails + 1))
        printf '  FAIL  %-28s\n' "$name"
        printf '        - %s\n' "${reasons[@]}"
        printf '        --- osslsigncode verify output ---\n'
        sed 's/^/        /' <<<"$out" | head -25
    fi
done

if [ "$fails" -ne 0 ]; then
    printf '\n::error::%s of %s Windows artifacts are not signed-and-timestamped — refusing to release\n' \
        "$fails" "${#files[@]}" >&2
    exit 1
fi

printf '\nverify-signatures: all %s artifacts signed and timestamped\n' "${#files[@]}"
