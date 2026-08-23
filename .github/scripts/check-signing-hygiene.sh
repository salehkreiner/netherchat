#!/usr/bin/env bash
#
# check-signing-hygiene.sh — the S3 protections, made mechanical.
#
# docs/release-signing.md states four things about the signing credential. A
# document that states them is a document; this script is what makes them fail
# the build when they stop being true:
#
#   1. the credential is reachable only from a tag-triggered job
#   2. a pull_request or workflow_dispatch trigger cannot reach it
#   3. a GitHub Environment gates the signing job
#   4. nothing in ci.yml can touch it
#
# It runs on every push and every pull request (signing-hygiene.yml), which is
# the point: the release workflow itself only runs on a tag, so a change that
# opened the credential up would otherwise sit on main unnoticed until someone
# tagged a release.
#
# WHAT IT PARSES. GitHub workflows are YAML, and this reads them with awk. That
# is a real limitation and it is handled by refusing what it cannot read rather
# than guessing: flow-style `on: {push: …}` and a quoted `"on":` key are hard
# failures, not silently-skipped cases. Everything else it checks is a token —
# a secret name, a filename, a permission — where a text match is the honest
# tool. Each check names what it looked at.
#
# Every check in here has been landed red on purpose; see
# docs/phase5-release-signing (the constructed-failure section) for the output.
#
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2   # repo root

WF=".github/workflows"
RELEASE="$WF/release.yml"
CI="$WF/ci.yml"
SEAM=".github/scripts/sign-windows.sh"

# The four halves of the signing credential. Adding a fifth means adding it here.
SECRET_RE='ESIGNER_(USERNAME|PASSWORD|CREDENTIAL_ID|TOTP_SECRET)'

fails=0
fail() { printf '::error::%s\n' "$*" >&2; fails=$((fails + 1)); }
pass() { printf '  ok    %s\n' "$*"; }

# Extract the block belonging to a top-level key (column 0), excluding the key
# line itself. Stops at the next column-0 key.
top_block() {
    awk -v key="$2" '
        /^[A-Za-z_"][A-Za-z0-9_-]*"?:/ { inb = ($0 ~ "^" key ":") ? 1 : 0; if (inb) next }
        inb { print }
    ' "$1"
}

# First and last line numbers of a job block (jobs are at two-space indent).
job_range() {
    awk -v job="$2" '
        $0 ~ "^  " job ":" { start = NR; inb = 1; next }
        inb && /^  [A-Za-z_]/ { print start ":" (NR - 1); exit }
        END { if (inb) print start ":" NR }
    ' "$1"
}

echo "signing hygiene:"

[ -f "$RELEASE" ] || { fail "$RELEASE does not exist"; exit 1; }
[ -f "$CI" ]      || { fail "$CI does not exist"; exit 1; }
[ -f "$SEAM" ]    || { fail "$SEAM does not exist"; exit 1; }

# --- 1 + 2. The trigger surface of the release workflow ----------------------
if grep -qE '^on:[[:space:]]*[[{]' "$RELEASE"; then
    fail "rule 1/2: $RELEASE uses flow-style 'on:' — this checker will not guess at it"
elif grep -qE '^"on":' "$RELEASE"; then
    fail "rule 1/2: $RELEASE uses a quoted 'on' key — this checker will not guess at it"
else
    on_block=$(top_block "$RELEASE" "on")
    if [ -z "$on_block" ]; then
        fail "rule 1/2: could not find an 'on:' block in $RELEASE"
    else
        triggers=$(printf '%s\n' "$on_block" \
            | grep -E '^  [A-Za-z_]' | sed -e 's/^  //' -e 's/:.*//' | sort -u)
        unexpected=$(printf '%s\n' "$triggers" | grep -vx 'push' || true)
        if [ -n "$unexpected" ]; then
            fail "rule 1/2: $RELEASE is triggered by more than a tag push — found: $(printf '%s' "$unexpected" | tr '\n' ' ')"
        else
            pass "rule 1/2: $RELEASE triggers on 'push' only"
        fi
        if printf '%s\n' "$on_block" | grep -qE '^    branches:'; then
            fail "rule 1: $RELEASE has a branch trigger — the signing job must be reachable only from a tag"
        else
            pass "rule 1: no branch trigger"
        fi
        if printf '%s\n' "$on_block" | grep -qE '^    tags:'; then
            pass "rule 1: tag filter present"
        else
            fail "rule 1: $RELEASE 'push' trigger has no tags: filter"
        fi
    fi
fi

# --- 3. The signing job is gated by an Environment ---------------------------
range=$(job_range "$RELEASE" "sign-windows")
if [ -z "$range" ]; then
    fail "rule 3: no 'sign-windows' job in $RELEASE"
else
    start=${range%%:*}; end=${range##*:}
    job=$(sed -n "${start},${end}p" "$RELEASE")

    if printf '%s\n' "$job" | grep -qE '^    environment:'; then
        pass "rule 3: sign-windows declares an environment"
    else
        fail "rule 3: the sign-windows job declares no 'environment:' — its secrets would be repository-wide"
    fi

    # The signer must not be able to publish. This is the half of the split that
    # keeps a compromised signing step from putting its output on a release page.
    perms=$(printf '%s\n' "$job" | awk '/^    permissions:/{p=1;next} p&&/^    [a-z]/{exit} p')
    if printf '%s\n' "$perms" | grep -qE 'write'; then
        fail "rule 3: sign-windows requests a write permission — the job that signs must not be able to publish"
    else
        pass "rule 3: sign-windows holds no write permission"
    fi

    # Every reference to the credential lives inside that job.
    stray=$(grep -nE "secrets\.$SECRET_RE" "$RELEASE" \
        | awk -F: -v s="$start" -v e="$end" '$1 < s || $1 > e {print $1}')
    if [ -n "$stray" ]; then
        fail "rule 3: $RELEASE references a signing secret outside the sign-windows job, at line(s): $(printf '%s' "$stray" | tr '\n' ' ')"
    else
        pass "rule 3: every signing-secret reference is inside sign-windows"
    fi
fi

# --- 4. Nothing in ci.yml can touch it ---------------------------------------
if grep -qE "$SECRET_RE" "$CI"; then
    fail "rule 4: $CI references a signing secret"
else
    pass "rule 4: $CI references no signing secret"
fi
if grep -qE '^\s+environment:' "$CI"; then
    fail "rule 4: $CI declares an 'environment:' — it runs on every push and must never be able to claim one"
else
    pass "rule 4: $CI declares no environment"
fi
if grep -q 'sign-windows.sh' "$CI"; then
    fail "rule 4: $CI invokes the signing script"
else
    pass "rule 4: $CI does not invoke the signing script"
fi

# --- The seam is one place ----------------------------------------------------
holders=$(grep -lE "secrets\.$SECRET_RE" "$WF"/*.yml 2>/dev/null | sort || true)
if [ "$holders" != "$RELEASE" ]; then
    fail "seam: exactly one workflow may reference the signing secrets; found: ${holders:-none}"
else
    pass "seam: only $RELEASE references the signing secrets"
fi

# Keyed on the INVOCATION form, not on any mention of the filename. The first
# version of this check counted mentions and failed on its own documentation:
# release.yml names the script in a header comment, and signing-hygiene.yml hands
# the path to shellcheck. Neither of those runs it. Naming the seam is allowed;
# running it is what is restricted to one place.
INVOKE='bash .github/scripts/sign-windows.sh'

callers=$(grep -lF "$INVOKE" "$WF"/*.yml 2>/dev/null | sort || true)
if [ "$callers" != "$RELEASE" ]; then
    fail "seam: exactly one workflow may run the signing script; found: ${callers:-none}"
else
    pass "seam: only $RELEASE runs the signing script"
fi

n=$(grep -cF "$INVOKE" "$RELEASE" || true)
if [ "$n" != "1" ]; then
    fail "seam: the signing script is run $n times in $RELEASE — the seam is meant to be one step"
else
    pass "seam: the signing script is run exactly once"
fi

# --- The signature check cannot be skipped ------------------------------------
# A verify step with `continue-on-error` or an `if:` is a verify step that can be
# green without running, which is the same defect as not having one.
#
# Scoped to the step, not the file: it collects each `- ` step block and reports
# only the blocks that actually run verify-signatures.sh. `-B<n>` context would
# make the answer depend on how many comment lines happen to precede the step.
if ! grep -q 'verify-signatures\.sh' "$RELEASE"; then
    fail "seam: $RELEASE never runs verify-signatures.sh"
else
    # A step block starts at `      - ` and ends at the next one. Any step block
    # that runs the verifier must contain neither `if:` nor `continue-on-error:`.
    skippable=$(awk '
        /^      - / {
            if (has && cond) print name;
            blk = ""; has = 0; cond = 0; name = $0
        }
        { blk = blk $0 "\n" }
        /verify-signatures\.sh/ { has = 1 }
        /^ +(continue-on-error|if):[[:space:]]/ { cond = 1 }
        END { if (has && cond) print name }
    ' "$RELEASE")
    if [ -n "$skippable" ]; then
        fail "seam: a step that runs verify-signatures.sh carries if: or continue-on-error: —$skippable"
    else
        pass "seam: no step that runs verify-signatures.sh is skippable"
    fi
    n_verify=$(grep -c 'bash .github/scripts/verify-signatures.sh' "$RELEASE" || true)
    if [ "$n_verify" -lt 1 ]; then
        fail "seam: $RELEASE does not run verify-signatures.sh"
    else
        pass "seam: verify-signatures.sh runs $n_verify time(s)"
    fi
fi

echo
if [ "$fails" -ne 0 ]; then
    printf '::error::signing hygiene: %s check(s) failed\n' "$fails" >&2
    exit 1
fi
echo "signing hygiene: all checks passed"
