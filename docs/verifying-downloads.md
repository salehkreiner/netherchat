# Verifying what you downloaded

Two checks, and they answer two different questions. Conflating them is the most
common mistake in software distribution, and this page exists because Netherchat's
documentation is precise about that distinction everywhere else.

| | Question | Proves | Available on |
|---|---|---|---|
| **SHA-256 checksum** | did these bytes arrive intact? | **integrity of transfer** | every platform |
| **Authenticode signature** | who built this? | **origin**, and integrity since signing | Windows only |

---

## The checksum proves transfer, not origin

Every release publishes `checksums.txt` with a SHA-256 for every archive.

```sh
# Linux
sha256sum -c --ignore-missing checksums.txt

# macOS
shasum -a 256 -c --ignore-missing checksums.txt
```

```powershell
# Windows
(Get-FileHash .\netherchat_windows_amd64.zip -Algorithm SHA256).Hash
# compare against the matching line in checksums.txt
```

**What that tells you:** the archive you have is byte-for-byte the archive whose
hash is in that file. It catches a truncated download, a corrupted mirror, a
proxy that mangled the transfer.

**What it does not tell you:** who produced the archive. `checksums.txt` is
published on the same page, over the same connection, by the same account as the
download it describes. Anyone who can replace the archive can replace the line
that describes it. A checksum beside a download is a self-consistency check, and
a hostile release page is perfectly self-consistent.

It is worth being blunt about this because "SHA-256 verified" reads like a
security guarantee and is routinely quoted as one. It is a *transfer* guarantee.
The signature is the origin guarantee.

---

## The signature proves origin (Windows)

```powershell
Get-AuthenticodeSignature .\netherchat.exe |
  Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

What you want to see:

- **`Status : Valid`** — the signature verifies and its certificate chains to a
  root this machine trusts.
- **`SignerCertificate`** with a subject containing **`O=Astralis Software
  Systems`**. Read this one. `Valid` on its own only means *somebody* the machine
  trusts signed it, and "somebody" includes every code-signing CA in the world.
- **`TimeStamperCertificate`** not null — the signature carries an RFC 3161
  timestamp, so it keeps verifying after the signing certificate expires.

This is the check that survives a compromised release page, because the private
key is not on the release page. Windows performs it itself on every launch under
Smart App Control, Windows Defender Application Control, and AppLocker publisher
rules.

Statuses that mean **stop**:

| `Status` | What happened |
|---|---|
| `HashMismatch` | signed, then modified. Do not run it. |
| `NotTrusted`, `UnknownError` | the chain does not reach a trusted root — the signature is real but the signer is not one this machine accepts |
| `NotSigned` on a release that should be signed | you did not get what the release page describes |

`installer/install.ps1` applies exactly this policy: a signature that is present
but does not lead back to Astralis, or one over modified bytes, stops the install
outright. It is the dangerous case that is fail-closed today, before the
certificate even exists.

---

## Current state: Netherchat releases are not signed yet

An OV code-signing certificate is being acquired; validation is blocked on a
D-U-N-S number. Until it completes:

- **Windows binaries carry no signature.** `install.ps1` says so, in as many
  words, and installs anyway — refusing every release in existence is not a
  security posture. What it will not do is accept a *wrong* signature.
- **Smart App Control and WDAC will block these binaries.** That is them working
  correctly. There is no honest workaround to offer; the fix is the certificate.
- `docs/release-signing.md` is the pipeline and the swap checklist.

Releases produced before the certificate exists are **prereleases**, and the
release workflow refuses to publish a full release without one.

---

## macOS and Linux

Not code-signed, and macOS binaries are not notarized — there is no Apple
Developer ID certificate. On those platforms the checksum is the only check
available, and per the top of this page that is a claim about transfer and not
about origin. Two things partly close the gap:

- **Homebrew** carries the expected SHA-256 inside the cask, in the tap
  repository, which is a *different* repository from the one serving the
  download. That is a meaningfully stronger position than a checksum published
  next to its own artifact.
- **Building from source** — `go build ./cmd/...` with Go 1.26+ — removes the
  question entirely. The tree is AGPL and the build is reproducible enough that
  this is a real option, not a formality.

macOS may also quarantine a browser-downloaded archive (`com.apple.quarantine`),
which produces a Gatekeeper prompt. Files fetched by `curl` inside `install.sh`
are not quarantined, so the installer path does not hit it. The absence of a
prompt is not evidence of a signature.

---

## If a check fails

**Checksum mismatch.** Do not run the binary and do not retry into the same
place. Both installers refuse outright — a mismatch is evidence of a problem, not
an absence of evidence, and `--allow-unverified` / `-AllowUnverified` does not
override it. Fetch again from
`https://github.com/astralis-software-systems/netherchat/releases`, and if it
mismatches twice, say so at
[SECURITY.md](../SECURITY.md).

**Signature not `Valid` on a release that should be signed.** Same: stop, and
report it. This is the case a signature exists to detect.

**No checksum available at all.** Both installers refuse rather than install
something they could not check. `--allow-unverified` (POSIX) and
`-AllowUnverified` (Windows) exist to accept that deliberately, have to be typed
on the command line, are honoured from no environment variable, and print what
they skipped. They relax the *absence* of a checksum. They never relax a checksum
that is present and wrong, and they never relax the signature rules.
