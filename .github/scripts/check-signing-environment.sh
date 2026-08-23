#!/usr/bin/env bash
#
# check-signing-environment.sh — the gate, as configured, not as documented.
#
# WHY THIS EXISTS. release.yml's sign-windows job declares
# `environment: release-signing`, and check-signing-hygiene.sh asserts that the
# line is there. Neither of them could see what was on the other side of it.
#
# What was on the other side of it, for both real runs of this workflow, was
# nothing. GitHub auto-creates an environment the first time a job names one,
# and the one it created had:
#
#     "protection_rules": []
#
# No required reviewer, no tag restriction. Every word of docs/release-signing.md
# section 3 was true about what a maintainer was supposed to configure and false
# about what was configured. The `environment:` line was load-bearing for a
# property nothing was enforcing, and the only way to find that out was to ask
# the API — a settings page nobody revisits is exactly the guard class this
# project keeps finding.
#
# So: the file-parsing guard checks that the job names an environment, and this
# one checks that the environment named is a gate. They are separate scripts
# because they fail for separate reasons — check-signing-hygiene.sh reads three
# files in the checkout and needs no network, no token and no repository, and
# that is worth keeping true.
#
# FAILS CLOSED, including when it cannot read. An unreadable answer and an empty
# answer are reported differently, so a re-run and a fix are told apart, but both
# are red. A guard that goes green because it could not check is the defect this
# script was written about.
#
# Needs curl and jq. Both are preinstalled on ubuntu-latest.
#
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2   # repo root

RELEASE=".github/workflows/release.yml"
API="${GITHUB_API_URL:-https://api.github.com}"

fails=0
fail() { printf '::error::%s\n' "$*" >&2; fails=$((fails + 1)); }
pass() { printf '  ok    %s\n' "$*"; }
note() { printf '  note  %s\n' "$*"; }

for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf '::error::%s is required and not installed\n' "$tool" >&2
        exit 2
    }
done

echo "signing environment:"

# --- Which environment, and which repository ---------------------------------
#
# The name is read out of release.yml rather than hardcoded. Renaming the
# environment in the workflow without renaming it in GitHub is a way to end up
# with an ungated job again, and a checker pinned to the old name would keep
# passing while pointed at an environment nothing uses.
[ -f "$RELEASE" ] || { fail "$RELEASE does not exist"; exit 1; }

ENV_NAME=$(awk '
    /^  sign-windows:/  { inb = 1; next }
    inb && /^  [A-Za-z_]/ { exit }
    inb && /^    environment:/ {
        sub(/^    environment:[[:space:]]*/, ""); gsub(/["'\'']/, ""); print; exit
    }
' "$RELEASE")

if [ -z "$ENV_NAME" ]; then
    fail "no 'environment:' on the sign-windows job in $RELEASE — nothing to check"
    exit 1
fi
pass "$RELEASE gates sign-windows on environment '$ENV_NAME'"

REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
    # Local runs: derive it from the remote, so this is runnable by hand.
    REPO=$(git config --get remote.origin.url 2>/dev/null \
        | sed -e 's#^git@github\.com:#https://github.com/#' \
              -e 's#^https://github\.com/##' -e 's#\.git$##')
fi
if [ -z "$REPO" ]; then
    fail "cannot determine the repository (set GITHUB_REPOSITORY)"
    exit 1
fi

# --- Read it -----------------------------------------------------------------
#
# Token first, anonymous second. On a public repository both work, and the
# fallback covers the case where the workflow token is scoped without the
# Environments permission while the same data is world-readable. If neither
# returns 200 the script stops: it will not report on rules it did not read.
api_get() {
    local url="$1" out="$2" code=""
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        code=$(curl -sS -o "$out" -w '%{http_code}' \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" "$url" 2>/dev/null) || code="000"
        [ "$code" = "200" ] || code=""
    fi
    if [ -z "$code" ]; then
        code=$(curl -sS -o "$out" -w '%{http_code}' \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" "$url" 2>/dev/null) || code="000"
    fi
    printf '%s' "$code"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
env_json="$tmp/env.json"
pol_json="$tmp/policies.json"

code=$(api_get "$API/repos/$REPO/environments/$ENV_NAME" "$env_json")
if [ "$code" != "200" ]; then
    if [ "$code" = "404" ]; then
        fail "environment '$ENV_NAME' does not exist on $REPO, or is not readable (HTTP 404).
        A job naming an environment that does not exist still runs; it just runs ungated."
    else
        fail "could not read environment '$ENV_NAME' on $REPO (HTTP $code).
        This is a red build on purpose: the gate was not checked, so it is not known to be there."
    fi
    exit 1
fi
jq -e . "$env_json" >/dev/null 2>&1 || { fail "environment response was not JSON"; exit 1; }

# --- 1. The headline: protection_rules is not empty --------------------------
n_rules=$(jq -r '.protection_rules | length' "$env_json")
rule_types=$(jq -r '[.protection_rules[].type] | join(", ")' "$env_json")
if [ "$n_rules" -eq 0 ]; then
    fail "environment '$ENV_NAME' has \"protection_rules\": [] — it gates nothing.
        GitHub creates an environment on first use with no rules at all, so the
        'environment:' line in $RELEASE buys exactly nothing until they are set.
        Settings -> Environments -> $ENV_NAME. docs/release-signing.md section 3 is the table."
else
    pass "protection_rules is not empty ($n_rules: $rule_types)"
fi

# --- 2. A human approves every use of the key --------------------------------
n_reviewers=$(jq -r '[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]?] | length' "$env_json")
# The `//` is applied per reviewer, after `.reviewers[]?` has yielded one: a
# team reviewer carries .slug where a user carries .login, and putting the
# alternation outside the iteration makes it re-iterate the whole list.
reviewers=$(jq -r '[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]? | (.reviewer.login // .reviewer.slug // "?")] | join(", ")' "$env_json")
if [ "$n_reviewers" -ge 1 ]; then
    pass "required reviewers: $reviewers"
else
    fail "environment '$ENV_NAME' has no required reviewers.
        Every use of the signing key is supposed to be approved by a person and
        recorded in the deployment log; without this it is approved by whoever
        can push a tag."
fi

# The gate says a human approves. With one reviewer who is also the person who
# pushes the tag, that human is the same human — which is the honest reading of
# what this proves, and not something a one-maintainer project can fix by
# turning prevent_self_review on: it would deadlock every release.
self=$(jq -r '[.protection_rules[] | select(.type == "required_reviewers") | .prevent_self_review] | first' "$env_json")
if [ "$self" = "false" ]; then
    note "prevent_self_review is off: the tag pusher may approve their own signing run."
    note "      With a single maintainer that is unavoidable. It is what the gate proves, not a defect."
fi

# --- 3. Only a v* tag can reach it -------------------------------------------
#
# This is the half GitHub enforces server-side: it is what stops a job on a
# branch from obtaining the secrets even if release.yml is edited to try.
# Classified inside jq, and deliberately without the `//` operator: `//` treats
# `false` as empty, so `.protected_branches // "null"` reads back "null" for the
# correctly-configured case, which is the value that means "unset". Comparing
# booleans explicitly keeps the three states apart.
policy=$(jq -r '
    if   .deployment_branch_policy == null                     then "none"
    elif .deployment_branch_policy.protected_branches == true   then "protected-branches"
    elif .deployment_branch_policy.custom_branch_policies == true then "custom"
    else "unknown" end' "$env_json")

case "$policy" in
none)
    fail "environment '$ENV_NAME' has no deployment branch or tag policy — every ref can deploy to it,
        including any branch. It must be 'Selected' with a tag rule of v*."
    ;;
protected-branches)
    fail "environment '$ENV_NAME' is restricted to protected BRANCHES, not to tags.
        The signing job must be reachable from a v* tag and from nothing else."
    ;;
unknown)
    fail "environment '$ENV_NAME' has a deployment policy this script does not recognise:
        $(jq -c '.deployment_branch_policy' "$env_json")"
    ;;
custom)
    code=$(api_get "$API/repos/$REPO/environments/$ENV_NAME/deployment-branch-policies" "$pol_json")
    if [ "$code" != "200" ]; then
        fail "could not read the deployment branch policies for '$ENV_NAME' (HTTP $code)"
    else
        n_branch=$(jq -r '[.branch_policies[] | select(.type == "branch")] | length' "$pol_json")
        tags=$(jq -r '[.branch_policies[] | select(.type == "tag") | .name] | join(" ")' "$pol_json")
        branches=$(jq -r '[.branch_policies[] | select(.type == "branch") | .name] | join(" ")' "$pol_json")

        if [ "$n_branch" -ne 0 ]; then
            fail "environment '$ENV_NAME' allows deployment from branch(es): $branches.
        The whole point of the tag rule is that a branch cannot reach the signing key."
        else
            pass "no branch may deploy to '$ENV_NAME'"
        fi

        if [ -z "$tags" ]; then
            fail "environment '$ENV_NAME' has no tag rule — with custom policies on and no rule, no
                tag matches, and the signing job will hang awaiting a deployment that cannot start."
        else
            # release.yml triggers on tags: ["v*"]. A rule broader than that (a
            # bare '*') would let a tag the workflow itself refuses reach the
            # environment, so every rule has to be at least as narrow.
            #
            # Read one per line rather than splitting the joined string: the
            # value most worth catching here is literally `*`, and an unquoted
            # expansion of it globs against the checkout instead of comparing.
            wide=""
            while IFS= read -r t; do
                [ -n "$t" ] || continue
                case "$t" in v*) ;; *) wide="$wide $t" ;; esac
            done < <(jq -r '.branch_policies[] | select(.type == "tag") | .name' "$pol_json")
            if [ -n "$wide" ]; then
                fail "environment '$ENV_NAME' has tag rule(s) that do not start with 'v':$wide.
        release.yml triggers on v* only; a rule wider than the trigger is a rule
        that admits refs the workflow does not."
            else
                pass "tag rule(s): $tags"
            fi
        fi
    fi
    ;;
esac

# --- 4. And an admin cannot walk around it -----------------------------------
bypass=$(jq -r '.can_admins_bypass' "$env_json")
if [ "$bypass" = "true" ]; then
    fail "environment '$ENV_NAME' lets administrators bypass its protection rules.
        The reviewer requirement above is then advisory for exactly the accounts most
        worth requiring it of. Settings -> Environments -> $ENV_NAME -> uncheck
        'Allow administrators to bypass configured protection rules'."
else
    pass "administrators cannot bypass the protection rules"
fi

echo
if [ "$fails" -ne 0 ]; then
    printf '::error::signing environment: %s check(s) failed\n' "$fails" >&2
    exit 1
fi
echo "signing environment: all checks passed"
