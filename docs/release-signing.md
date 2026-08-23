# Release signing

How a Netherchat Windows binary gets signed, what stops anything else from
signing one, and exactly what changes when the real certificate arrives.

If you are a *user* trying to check a download you already have, you want
[verifying-downloads.md](verifying-downloads.md) instead.

---

## Why this exists

Unsigned binaries are the adoption blocker, not a polish item. Windows Defender
Application Control and AppLocker evaluate publisher rules; Smart App Control
blocks unsigned executables outright, with no user override. Government and
enterprise fleets run all three. On the development machine that built this
pipeline, Smart App Control has blocked a hand-invoked CLI binary, freshly built
Go **test** binaries, and `wails.exe` — which is why the CipherSigil desktop
Console has never been launched there. That machine is a preview of the customer.

The second reason is the one that decides how the pipeline is *shaped*. A
workflow that can sign is a workflow that can ship malware signed as Astralis. A
code-signing certificate is a trust anchor: it is the thing that makes a Windows
machine run a binary it would otherwise refuse. Losing control of it is not a bug
for a security vendor, it is the end of the company. Everything below follows
from treating the credential that way.

---

## What gets signed

Sixteen binaries live under `cmd/`. Three of them are what a person runs on
Windows, and those are the ones that are signed:

| Binary | Who runs it | Signed |
|---|---|---|
| `netherchat.exe` | every participant — the endpoint client | **yes** |
| `netherchat-server.exe` | a self-hoster running the relay on Windows | **yes** |
| `netherchat-identity.exe` | whoever runs the issuing authority | **yes** |
| the other thirteen `netherchat-*` adapters | a relay operator, next to the relay | no |

The thirteen adapters are server-side connectors — Slack, Teams, SIEM, paging,
ITSM, CI/CD, and the ingress adapters. `docs/connectors.md` and
`docs/nc5-connectors.md` already state that they are built from source and that
"releases and the Docker image ship only `netherchat` and `netherchat-server`".
Nobody downloads them onto a workstation, so nobody hits Smart App Control with
one.

**Signature volume is metered.** The SSL.com eSigner base tier allows 240
signatures per year. Three binaries across two architectures is **six per
release**, so forty releases a year. Signing all sixteen would be thirty-two per
release — seven releases a year, and the tier would be the release cadence. That
is the whole reason the table above is a decision and not a list of everything
that compiles.

The three signed binaries are also **archived together**, so `-WithServer` needs
no second download and the issuing tool is in the same zip as the client that
verifies its output.

### macOS and Linux

Unchanged, with one addition. Their archives are built by GoReleaser exactly as
before, and they are **not** code-signed — there is no Apple Developer ID
certificate and none is in scope here, so macOS binaries are also not notarized.
For those platforms the SHA-256 in `checksums.txt` is the only check there is,
and [verifying-downloads.md](verifying-downloads.md) says plainly that it is a
weaker claim than a signature.

The addition: `netherchat-identity` now ships in the linux and darwin archives
too. `self-hosting.md` has always told an operator to run `netherchat-identity
keygen` and never said where to get it, because it shipped in no release for any
platform. One caveat on macOS specifically: the Homebrew cask links only
`netherchat` onto `PATH`. `netherchat-server` and `netherchat-identity` are
inside the archive but are not symlinked by `brew`, so Homebrew users who want
them should take them from the release archive directly.

---

## The pipeline

`.github/workflows/release.yml`, triggered only by pushing a `v*` tag.

```
build-windows            sign-windows                    release
─────────────            ────────────                    ───────
cross-compile     ──▶    THE SEAM: sign + timestamp ──▶  re-verify
6 unsigned .exe          verify signed + timestamped     package zips
                                                         goreleaser (linux+darwin)
no credential            signing credential              checksums + upload
contents: read           contents: READ                  contents: WRITE
                         environment: release-signing    no signing credential
```

**The job that can sign cannot publish, and the job that can publish cannot
sign.** `sign-windows` holds the credential and `permissions: contents: read`,
so it cannot create a release, upload an asset, or move a tag. `release` holds
`contents: write` and no signing secret. Compromising either one alone does not
put a signed artifact on a Netherchat release page.

Windows is deliberately absent from `.goreleaser.yaml`. GoReleaser builds its own
binaries; leaving Windows in it would publish an unsigned `netherchat.exe`
alongside the signed one, under the same filename the installers fetch by. The
Windows zips are built in the `release` job from the signed binaries and their
hashes are appended to the same `checksums.txt` GoReleaser wrote, so there is one
checksum file for the whole release — which is what both installers expect.

**`dist/` is GoReleaser's and `pkg/` is the workflow's.** GoReleaser runs with
`--clean`, whose first act is to delete `dist/` wholesale, so nothing else may
stage anything there: the second real run wrote the Windows zips into `dist/`
before GoReleaser ran, and both signed, timestamped, verified archives were
deleted four steps before anything looked for them. The zips are written to
`pkg/`, which GoReleaser neither reads nor writes.

The one deliberate crossing is `checksums.txt`, because the whole release needs
exactly one of them. That single append is therefore the only step in
`release.yml` whose position in the file is load-bearing, and it refuses to run
if `dist/checksums.txt` is not already there — moving it back above GoReleaser
fails loudly instead of writing to a file GoReleaser then deletes.

---

## The four protections, and how each is enforced

### 1. The credential is reachable only from a tag-triggered job

Three independent mechanisms, because any one of them can be edited away.

- **The trigger surface.** `release.yml` has exactly one trigger: `push` with a
  `tags: ["v*"]` filter. No `pull_request`, `workflow_dispatch`, `workflow_call`,
  `schedule`, or `repository_dispatch`.
- **A ref guard inside the job**, before the seam. It fails unless
  `github.event_name` is `push`, `github.ref_type` is `tag`, and `github.ref`
  starts with `refs/tags/v`. The ref is passed through `env:` rather than
  interpolated into the shell — a tag name is attacker-controllable text, and
  `${{ github.ref }}` pasted into a `run:` block is a script-injection sink.
- **The Environment's deployment rule**, which is the one GitHub enforces
  server-side and the one that survives someone editing this file. See below.

### 2. A `pull_request` or `workflow_dispatch` trigger cannot reach it

- The workflow does not run on either trigger, so there is no job to reach it
  from.
- If someone adds one, the ref guard fails the job before the signing step.
- If someone removes the ref guard too, the Environment's tag rule still refuses
  to inject the secrets, because that decision is GitHub's and not the workflow's.
- And `.github/workflows/signing-hygiene.yml` fails the build on the *pull
  request that proposes any of it* — see "The guard" below.

Worth stating separately: a `pull_request` from a fork never receives repository
secrets at all, and its `GITHUB_TOKEN` is read-only. That is GitHub's own rule
and it is not something this repository can weaken. The protections above are for
the case that rule does not cover — a branch or a dispatch inside the repository.

### 3. A GitHub Environment with protection rules gates the signing job

`sign-windows` declares `environment: release-signing`. GitHub injects an
environment's secrets only into a job that names the environment *and* whose ref
satisfies the environment's deployment policy.

**A maintainer must configure this once**, in Settings → Environments →
`release-signing`:

| Setting | Value | What it buys |
|---|---|---|
| Deployment branches and tags | **Selected** → tag rule `v*` | a job on a branch cannot obtain the secrets, even if `release.yml` is edited to try |
| Required reviewers | at least one maintainer | a human approves every use of the signing key, and every approval is recorded in the deployment log |
| Wait timer | optional | a window to cancel a release triggered by a stolen push |
| `ESIGNER_*` secrets | stored **here**, as environment secrets | anything that omits `environment:` cannot see them, including every job in `ci.yml` |

The secrets must be **environment** secrets, not repository secrets. A repository
secret is visible to any job in any workflow that asks for it, which would make
every other protection here decorative.

Until the certificate exists, none of these secrets are set, and the pipeline
signs with a throwaway certificate that needs no secret at all — so an
unconfigured environment costs nothing today and is required before the swap.

#### "A maintainer must configure this once" is not a guarantee, and it was not true

The first two runs of the release workflow ran against an environment that
looked exactly like the one above from inside `release.yml` and had nothing in
it. GitHub **auto-creates** an environment the moment a job names one, with:

```json
"protection_rules": []
```

No reviewer, no tag rule. `sign-windows` declared `environment: release-signing`,
the hygiene guard confirmed the line was there, this table said what the setting
should be — and the gate was a word in a YAML file. It was found by asking the
API, which is the only place the answer lives.

`.github/scripts/check-signing-environment.sh` now asks on every push and every
pull request. It reads the environment **name out of `release.yml`** rather than
hardcoding it, so renaming the environment in one place and not the other is
also caught, and it fails when:

| It fails when | Because |
|---|---|
| `protection_rules` is empty | this is the state found; the gate exists in name only |
| there are no required reviewers | the key is then used on whatever a tag push says, unreviewed |
| there is no deployment policy, or it selects branches | a branch could reach the signing key |
| a tag rule does not start with `v` | a rule wider than `release.yml`'s own `v*` trigger admits refs the workflow refuses |
| administrators may bypass the rules | the reviewer requirement is then advisory for exactly the accounts most worth requiring it of |
| the API cannot be read at all | a guard that goes green because it could not check is the defect this script is about |

It notes, without failing, that `prevent_self_review` is off. With one
maintainer it has to be: the person who pushes the tag approves the signing run.
That is what this gate proves, and it is worth stating rather than reading the
table above as though a second person were involved.

### 4. Nothing in `ci.yml` can touch it

`ci.yml` is unchanged by this work and stays that way. It declares no
`environment:`, so it structurally cannot receive an environment secret, and it
references no signing secret and never invokes the signing script. The hygiene
guard asserts all three on every push and every pull request.

### The guard

`.github/scripts/check-signing-hygiene.sh` and
`.github/scripts/check-signing-environment.sh`, both run by
`.github/workflows/signing-hygiene.yml` on push and pull request.

They are two scripts because they fail for two reasons. The first reads three
files in the checkout and needs no network, no token and no repository — worth
keeping true, because it is the one that can be run by hand on a plane. The
second is about repository *settings*, which no file in the checkout records, so
it has to ask the API and can fail for reasons a contributor cannot fix locally.

The release workflow only runs on a tag, so a change that opened the credential
up — a `workflow_dispatch` added "just to test it", an `environment:` line lost
in a refactor, a secret copied into `ci.yml` — would sit on `main`, green, until
someone tagged a release. The guard is what makes that a red build instead.

The first checks the four rules above, plus: the signing script is *run* from
exactly one step in exactly one workflow; no step that runs the verifier carries
`if:` or `continue-on-error:`; and the signing job requests no write permission.
The second checks that the environment rule 3 names is configured as rule 3 says
— the table is in section 3.

It is deliberately **not** part of `ci.yml`. `ci.yml` is the one workflow that
must be provably unable to reach a signing credential, and the cheapest way to
keep that provable is to leave it alone.

The guard reads YAML with `awk`, which is a real limitation, handled by refusing
what it cannot read: flow-style `on: {push: …}` and a quoted `"on":` key are hard
failures rather than silently-skipped cases.

---

## Timestamping

**An RFC 3161 timestamp is not optional, and the pipeline fails rather than
produce a signature without one.**

An Authenticode signature with no countersignature is valid only while the
signing certificate is valid. The CA/Browser Forum caps code-signing
certificates at **460 days**, so an untimestamped `v1.0` stops verifying roughly
fifteen months after it ships — on machines that ran it happily the day before,
with no change to the binary and nothing to point at. A timestamp pins the
signature to a moment inside the certificate's life, and it keeps verifying after
the certificate expires.

**The TSA is `http://ts.ssl.com`**, with `http://timestamp.digicert.com` and
`http://timestamp.sectigo.com` as fallbacks, tried in that order.

SSL.com's TSA is first because it is the one CodeSignTool uses. Picking it now
means the timestamp authority does not change on the day the certificate does —
one fewer variable in the swap. The fallbacks are there because a TSA outage
should not be a release outage; the signing report records which one answered.

**The presence of a timestamp is checked by reading the verifier's output, not
its exit code**, because `osslsigncode verify` exits `0` on a signature that has
no timestamp at all:

```
$ osslsigncode sign -pkcs12 leaf.p12 ... -in nc.exe -out nots.exe    # no -ts
Succeeded
$ osslsigncode verify -CAfile ca.crt -in nots.exe
Timestamp is not available
Signature verification: ok
Succeeded
$ echo $?
0
```

A verify step written as `osslsigncode verify … || exit 1` therefore passes an
artifact that will start failing for customers fifteen months later.
`.github/scripts/verify-signatures.sh` asserts on both the negative string
(`Timestamp is not available` must be absent) and the positive one (`Timestamp
Server Signature verification: ok` must be present).

---

## Verification, and what it asserts

`.github/scripts/verify-signatures.sh` runs twice — once in the signing job, once
in the publishing job, so the publisher does not take the signer's word for it.
For each artifact it requires:

1. `Signature verification: ok` against the pinned trust anchor
2. exactly one verified signature
3. a timestamp, both halves as above
4. a SHA-2 message digest — a SHA-1 Authenticode digest is rejected outright
5. a signer subject containing `Astralis Software Systems`

It takes a **directory**, not a file list, and enumerates every `*.exe` under it.
The failure this guard is really for is not "the signer produced a bad signature"
— it is "one artifact never reached the signer". A verify step handed an explicit
file list can be green while an unsigned binary sits next to the ones it checked.
`--expect-count 6` fails if the set is the wrong size at all.

One honest limit: in `selfsigned` mode the trust anchor comes from the signing
job, so the re-check in the publishing job proves integrity but not provenance.
In `esigner` mode the anchor is the system trust store and the check is genuinely
independent.

---

## The swap

The credential seam is **one step** — "sign Windows artifacts" in the
`sign-windows` job — calling `.github/scripts/sign-windows.sh`. That script has
two modes and nothing else in the pipeline knows which one ran.

### What changes

| | Before | After |
|---|---|---|
| Repository **variable** `SIGNING_MODE` | unset (defaults to `selfsigned`) | `esigner` |
| Environment secret `ESIGNER_USERNAME` | — | SSL.com account username |
| Environment secret `ESIGNER_PASSWORD` | — | SSL.com account password |
| Environment secret `ESIGNER_CREDENTIAL_ID` | — | eSigner credential ID for the signing certificate |
| Environment secret `ESIGNER_TOTP_SECRET` | — | the eSigner TOTP secret (used for automated signing) |
| `CODESIGNTOOL` in the sign step's `env:` | — | path to the CodeSignTool launcher |
| `installer/install.ps1` → `$RequireSignature` | `$false` | `$true` |

No YAML restructuring. No change to the verify step. No change to the release
job. The four secrets go into the `release-signing` **environment**, never the
repository.

### The checklist

1. **Configure the `release-signing` environment first** — tag rule `v*`,
   required reviewers, and the four secrets. Section 3 above is the table.
2. **Install CodeSignTool in the sign job** and set `CODESIGNTOOL`. The
   `esigner` branch of `sign-windows.sh` has **never executed**; confirm the flag
   names against SSL.com's current CodeSignTool documentation before relying on
   them, because they were written from the documented CLI and not from a run.
3. **Dry-run on a prerelease tag** — `v0.0.0-signtest`. Nothing about that tag is
   special except that the release job's prerelease gate lets it through in
   either mode, so a failure costs nothing.
4. **Read the signing report** on that release. It names the mode, the
   certificate subject, the TSA that answered, and the SHA-256 of every signed
   file. `certificate-source: SSL.com eSigner` is the line that says the swap
   took.
5. **Confirm the artifacts on a real Windows machine**, not in the job:

   ```powershell
   Get-AuthenticodeSignature .\netherchat.exe |
     Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
   ```

   The first genuinely-signed release is the one where all four of these hold:

   - `Status` is **`Valid`** — not `UnknownError`, which is what the throwaway
     certificate produces ("terminated in a root certificate which is not trusted")
   - `SignerCertificate.Subject` contains **`O=Astralis Software Systems`**
   - `TimeStamperCertificate` is **not null**
   - the binary launches on a machine with **Smart App Control on**. This is the
     only check that tests the thing the whole exercise is for, and it cannot be
     done from CI.

6. **Flip `$RequireSignature` to `$true`** in `installer/install.ps1`, so an
   unsigned build stops being acceptable to the installer. Do this *after* step 5,
   not before: it is the step that makes an unsigned release uninstallable.
7. **Tag a real release.** Until `SIGNING_MODE=esigner`, the release job refuses
   to publish a non-prerelease tag at all, so this is also the point at which
   full releases start working again.
8. **Update the risk register** — roadmap §9, "Code signing absent" — and
   §8's standing item about the growing bill.

### What is deliberately not automated

Nothing revokes, rotates, or renews the certificate. A 460-day cap means a
renewal is due inside the certificate's life, and a timestamped release survives
it; an untimestamped one does not, which is why step 5 checks
`TimeStamperCertificate` on a real machine rather than trusting the job.
