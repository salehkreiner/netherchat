#!/usr/bin/env bash
#
# sign-windows.sh — THE CREDENTIAL SEAM.
#
# This is the ONE place in the repository that touches a code-signing key. It is
# called from exactly one step, in exactly one job, in exactly one workflow
# (.github/workflows/release.yml, job `sign-windows`). Nothing else in this tree
# invokes it and nothing in ci.yml can reach it — see
# .github/scripts/check-signing-hygiene.sh, which fails the build if that stops
# being true.
#
# Two modes, selected by SIGNING_MODE:
#
#   selfsigned  (default, and the only mode that has ever run)
#               Generates a throwaway CA and code-signing leaf inside the job,
#               signs with it, and writes the CA to $SIGN_CA_OUT so the verify
#               step has a trust anchor. The key exists for the length of one job
#               and is never a secret. Binaries signed this way are NOT
#               distributable: Windows will reject them, which is the point —
#               they prove the pipeline, not the publisher.
#
#   esigner     SSL.com eSigner / CodeSignTool against the cloud HSM. Written,
#               reviewed, and NEVER EXECUTED — the certificate does not exist
#               yet. docs/release-signing.md §"The swap" is the checklist for
#               turning it on, and its first item is a dry run on an -rc tag.
#
# The swap is: set the repository variable SIGNING_MODE=esigner and populate the
# four ESIGNER_* environment secrets. No YAML changes, no step changes, no
# changes to the verify step. That is the whole seam.
#
# WHY A TIMESTAMP IS NOT OPTIONAL. An Authenticode signature with no RFC 3161
# countersignature is only valid while the signing certificate is valid. The
# CA/Browser Forum caps code-signing certificates at 460 days, so an
# untimestamped v1.0 stops verifying roughly fifteen months after it ships, on
# machines that were happy with it the day before. A timestamp pins the
# signature to a moment inside the certificate's life and it keeps verifying
# after the certificate expires. This script therefore FAILS rather than emit an
# untimestamped signature, and refuses to fall back to "sign without -ts".
#
# Usage:
#   sign-windows.sh <file.exe> [file.exe ...]
#
# Environment:
#   SIGNING_MODE      selfsigned | esigner            (default: selfsigned)
#   TSA_URLS          space-separated RFC 3161 URLs, tried in order
#   SIGN_CA_OUT       path to write the trust anchor  (selfsigned mode only)
#   SIGN_REPORT       path to write the signing report
#   OSSLSIGNCODE      osslsigncode binary             (default: osslsigncode)
#   PRODUCT_NAME      Authenticode description        (default: Netherchat)
#   PRODUCT_URL       Authenticode URL                (default: https://netherchat.com)
#   CODESIGNTOOL      CodeSignTool launcher           (esigner mode only)
#   ESIGNER_USERNAME  ESIGNER_PASSWORD                (esigner mode only)
#   ESIGNER_CREDENTIAL_ID  ESIGNER_TOTP_SECRET        (esigner mode only)
#
set -euo pipefail

MODE="${SIGNING_MODE:-selfsigned}"
OSSLSIGNCODE="${OSSLSIGNCODE:-osslsigncode}"
# ts.ssl.com first on purpose: it is the TSA CodeSignTool uses, so the day the
# real certificate arrives the timestamp authority does not change with it. The
# other two are there because a TSA outage should not be a release outage.
TSA_URLS="${TSA_URLS:-http://ts.ssl.com http://timestamp.digicert.com http://timestamp.sectigo.com}"
SIGN_CA_OUT="${SIGN_CA_OUT:-}"
SIGN_REPORT="${SIGN_REPORT:-}"
PRODUCT_NAME="${PRODUCT_NAME:-Netherchat}"
PRODUCT_URL="${PRODUCT_URL:-https://netherchat.com}"

die() { printf 'sign-windows: error: %s\n' "$*" >&2; exit 1; }
note() { printf 'sign-windows: %s\n' "$*" >&2; }

[ $# -gt 0 ] || die "no files given (usage: sign-windows.sh <file.exe> ...)"

# ---- input validation, before any credential is touched ---------------------
# A signing key should never be unlocked to discover the input was wrong. Every
# argument must exist and must actually be a PE image: osslsigncode will refuse
# a non-PE anyway, but it refuses AFTER the p12 is on disk, and a script that
# reports "not a PE file" without having generated a key is easier to trust.
for f in "$@"; do
    [ -f "$f" ] || die "not a file: $f"
    magic=$(head -c 2 "$f" | od -An -c | tr -d ' \n')
    [ "$magic" = "MZ" ] || die "not a PE image (no MZ header): $f"
done

report=""
add_report() { report="${report}$1"$'\n'; }
add_report "mode: $MODE"
add_report "files: $#"

case "$MODE" in
selfsigned) ;;
esigner) ;;
*) die "unknown SIGNING_MODE '$MODE' (expected 'selfsigned' or 'esigner')" ;;
esac

# =============================================================================
# selfsigned — the pre-certificate path
# =============================================================================
sign_selfsigned() {
    command -v "$OSSLSIGNCODE" >/dev/null 2>&1 || die "osslsigncode not found (set OSSLSIGNCODE)"

    work=$(mktemp -d)
    chmod 700 "$work"
    # shellcheck disable=SC2064  # $work is expanded now on purpose
    trap "rm -rf '$work'" EXIT INT TERM

    pass=$(openssl rand -hex 24)

    # THE CERTIFICATE IS BACKDATED ONE HOUR, AND THAT IS LOAD-BEARING.
    #
    # An Authenticode signature is verified as of its RFC 3161 timestamp, and
    # that timestamp comes from the TSA's clock, not this runner's. A certificate
    # minted with notBefore = "now" and used two seconds later fails verification
    # whenever the TSA's clock is a second behind — which is ordinary NTP skew,
    # not a fault. Measured here, with ts.ssl.com, on a certificate that was
    # valid from 01:17:00 and a timestamp of 01:16:59:
    #
    #     Error: certificate is not yet valid
    #     PKCS7_verify error
    #     Signature verification: failed
    #
    # It hit one artifact out of six, which is the worst possible shape for a
    # release job. `openssl req -x509` cannot backdate, and `-not_before` only
    # exists in OpenSSL 3.5+; `openssl ca -startdate` has worked since 1.x and is
    # what the runner will have. The real certificate has no such problem — an OV
    # certificate's notBefore is days in the past by the time it signs anything.
    mkdir -p "$work/db"
    : > "$work/db/index.txt"
    echo 1000 > "$work/db/serial"
    cat > "$work/openssl.cnf" <<'CNF'
[ ca ]
default_ca = throwaway
[ throwaway ]
dir              = .
database         = $dir/db/index.txt
serial           = $dir/db/serial
new_certs_dir    = $dir/db
certificate      = $dir/ca.crt
private_key      = $dir/ca.key
default_md       = sha256
policy           = anything
email_in_dn      = no
unique_subject   = no
preserve         = no
[ anything ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
[ v3_ca ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
[ v3_codesign ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = critical,codeSigning
subjectKeyIdentifier   = hash
CNF

    startdate=$(date -u -d '-1 hour' +%Y%m%d%H%M%SZ)
    enddate=$(date -u -d '+30 days' +%Y%m%d%H%M%SZ)

    note "generating a throwaway signing certificate (valid $startdate .. $enddate, never leaves this job)"
    (
        cd "$work" || exit 1
        openssl req -new -newkey rsa:3072 -keyout ca.key -out ca.csr -nodes \
            -subj "/C=US/O=Astralis Software Systems/CN=Astralis Development Signing Root (NOT A REAL CA)" 2>/dev/null
        openssl ca -batch -config openssl.cnf -selfsign -keyfile ca.key -in ca.csr \
            -out ca.crt -extensions v3_ca -startdate "$startdate" -enddate "$enddate" -notext 2>/dev/null

        openssl req -new -newkey rsa:3072 -keyout leaf.key -out leaf.csr -nodes \
            -subj "/C=US/O=Astralis Software Systems/CN=Astralis Software Systems (DEVELOPMENT BUILD - UNTRUSTED)" 2>/dev/null
        openssl ca -batch -config openssl.cnf -in leaf.csr -out leaf.crt \
            -extensions v3_codesign -startdate "$startdate" -enddate "$enddate" -notext 2>/dev/null
    ) || die "could not generate the throwaway certificate"
    [ -s "$work/ca.crt" ] && [ -s "$work/leaf.crt" ] || die "certificate generation produced nothing"

    openssl pkcs12 -export -out "$work/leaf.p12" -inkey "$work/leaf.key" -in "$work/leaf.crt" \
        -certfile "$work/ca.crt" -passout "pass:$pass" -name astralis-dev 2>/dev/null

    subject=$(openssl x509 -in "$work/leaf.crt" -noout -subject | sed 's/^subject=//')
    add_report "certificate: $subject"
    add_report "certificate-source: generated in-job (throwaway, untrusted by design)"

    if [ -n "$SIGN_CA_OUT" ]; then
        cp "$work/ca.crt" "$SIGN_CA_OUT"
        note "wrote trust anchor to $SIGN_CA_OUT"
    fi

    for f in "$@"; do
        signed=0
        for tsa in $TSA_URLS; do
            note "signing $f via $tsa"
            # osslsigncode will not overwrite in place, so sign to a sibling and move.
            if "$OSSLSIGNCODE" sign \
                -pkcs12 "$work/leaf.p12" -pass "$pass" \
                -h sha256 \
                -n "$PRODUCT_NAME" -i "$PRODUCT_URL" \
                -ts "$tsa" \
                -in "$f" -out "$f.signed" >"$work/sign.log" 2>&1; then
                mv "$f.signed" "$f"
                add_report "signed: $f  tsa=$tsa  sha256=$(sha256sum "$f" | cut -d' ' -f1)"
                signed=1
                break
            fi
            rm -f "$f.signed"
            note "TSA $tsa failed:"
            sed 's/^/    /' "$work/sign.log" >&2
        done
        # No fallback to an untimestamped signature. See the header.
        [ "$signed" -eq 1 ] || die "could not timestamp $f against any of: $TSA_URLS"
    done
}

# =============================================================================
# esigner — the post-certificate path. NEVER EXECUTED. See docs/release-signing.md.
# =============================================================================
sign_esigner() {
    # Fail closed on a half-configured credential. A missing TOTP secret must be
    # a refusal to sign, never a fallback to some other key.
    for v in ESIGNER_USERNAME ESIGNER_PASSWORD ESIGNER_CREDENTIAL_ID ESIGNER_TOTP_SECRET; do
        eval "val=\${$v:-}"
        [ -n "$val" ] || die "SIGNING_MODE=esigner but $v is empty — refusing to sign"
    done
    cst="${CODESIGNTOOL:-}"
    [ -n "$cst" ] || die "SIGNING_MODE=esigner but CODESIGNTOOL is not set"
    command -v "$cst" >/dev/null 2>&1 || [ -x "$cst" ] || die "CodeSignTool not executable: $cst"

    add_report "certificate: (SSL.com eSigner cloud HSM, credential ${ESIGNER_CREDENTIAL_ID:0:6}…)"
    add_report "certificate-source: SSL.com eSigner"

    for f in "$@"; do
        out_dir=$(mktemp -d)
        # CodeSignTool applies an RFC 3161 timestamp from ts.ssl.com itself; it
        # has no flag to disable that and no flag to point elsewhere. The verify
        # step does not take its word for it either way.
        "$cst" sign \
            -username="$ESIGNER_USERNAME" \
            -password="$ESIGNER_PASSWORD" \
            -credential_id="$ESIGNER_CREDENTIAL_ID" \
            -totp_secret="$ESIGNER_TOTP_SECRET" \
            -input_file_path="$f" \
            -output_dir_path="$out_dir" \
            || die "CodeSignTool failed on $f"
        [ -f "$out_dir/$(basename "$f")" ] || die "CodeSignTool produced no output for $f"
        mv "$out_dir/$(basename "$f")" "$f"
        rm -rf "$out_dir"
        add_report "signed: $f  tsa=http://ts.ssl.com (CodeSignTool built-in)  sha256=$(sha256sum "$f" | cut -d' ' -f1)"
    done
}

case "$MODE" in
selfsigned) sign_selfsigned "$@" ;;
esigner)    sign_esigner "$@" ;;
esac

if [ -n "$SIGN_REPORT" ]; then
    printf '%s' "$report" > "$SIGN_REPORT"
    note "wrote $SIGN_REPORT"
fi
printf '%s' "$report"
