#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Netherchat terminal client on Windows.
.DESCRIPTION
    Downloads the netherchat client for your architecture from GitHub releases,
    verifies its SHA-256, checks the Authenticode signature on every executable it
    is about to install, installs to %LOCALAPPDATA%\Programs\netherchat, and adds
    that directory to your user PATH. Installs the endpoint client only by
    default; pass -WithServer to also install the netherchat-server relay binary,
    which already ships in the same release archive (no extra download).

    TWO DIFFERENT QUESTIONS ARE ASKED, AND THEY ARE NOT THE SAME QUESTION. The
    SHA-256 says the bytes arrived intact; it is published on the same page as the
    download, so whoever can replace one can replace the other. The Authenticode
    signature says the bytes came from Astralis Software Systems and have not been
    altered since, and it is the only one of the two that survives a compromised
    release page. See docs/verifying-downloads.md.

    A download that cannot be checksummed is NOT installed (see
    -AllowUnverified). A binary signed by anyone other than Astralis, or signed
    and then modified, is NEVER installed.

    The unpinned form installs the latest release; pass -Version to pin one.
.PARAMETER Version
    Install a specific release instead of the latest one. Accepts either form,
    with or without the leading v (X.Y.Z and vX.Y.Z are equivalent). Defaults
    to the NETHERCHAT_VERSION environment variable, then to the latest release.
.PARAMETER AllowUnverified
    Install even if the checksum cannot be OBTAINED — a missing checksums.txt, or
    a release that publishes no entry for this archive. It never skips a checksum
    that is present and wrong, and it never relaxes the signature rules. There is
    deliberately no environment variable for this: it has to be typed.
.EXAMPLE
    irm https://netherchat.com/install.ps1 | iex
.EXAMPLE
    & ([scriptblock]::Create((irm https://netherchat.com/install.ps1))) -WithServer
.EXAMPLE
    & ([scriptblock]::Create((irm https://netherchat.com/install.ps1))) -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Version = $env:NETHERCHAT_VERSION,
    [string]$BinDir = $env:NETHERCHAT_BIN_DIR,
    [switch]$WithServer,
    [switch]$AllowUnverified,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Repo = 'astralis-software-systems/netherchat'
$Binary = 'netherchat.exe'
$ServerBinary = 'netherchat-server.exe'

# ---- signature policy -------------------------------------------------------
# THE ONE LINE THAT CHANGES WITH THE CERTIFICATE. Netherchat releases are not
# code-signed yet, so an unsigned build has to install — refusing every release
# in existence is not a security posture, it is a broken installer. What is NOT
# deferred is the dangerous half: a binary carrying a signature that does not
# lead back to Astralis, or one signed and then altered, is refused today.
# Absence of evidence warns; evidence of a problem stops.
#
# Set $RequireSignature to $true once the first eSigner-signed release is out,
# and unsigned stops being acceptable too. docs/release-signing.md, "The swap".
$RequireSignature = $false
$ExpectedSigner = 'O=Astralis Software Systems'

function Step($m) { Write-Host "> $m" -ForegroundColor Magenta }
function Ok($m) { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

if (-not $BinDir) { $BinDir = Join-Path $env:LOCALAPPDATA 'Programs\netherchat' }

# ---- Authenticode ------------------------------------------------------------
# Answers the question the checksum cannot: is this executable from Astralis?
# Called on every binary about to be written to the user's PATH, and it is the
# reason this installer checks anything at all beyond a hash published on the
# same page as the download it describes.
#
# Get-AuthenticodeSignature reports Valid only when the chain reaches a root this
# machine trusts, so a counterfeit signed with an attacker's own certificate does
# not land here as Valid — it lands as NotTrusted or UnknownError, which is fatal
# below. Every status other than Valid and NotSigned is fatal: an unreadable
# signature on an executable is a reason to stop, not a reason to guess.
function Assert-TrustedBinary($path) {
    $name = Split-Path -Leaf $path
    Step "Verifying signature of $name"
    $sig = Get-AuthenticodeSignature -FilePath $path

    switch ($sig.Status) {
        'Valid' {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -notlike "*$ExpectedSigner*") {
                Die "$name is signed, but not by Astralis Software Systems.`n       signer: $subject`n       Refusing to install it. This is what a counterfeit build looks like."
            }
            if ($sig.TimeStamperCertificate) {
                Ok "signed by $ExpectedSigner, timestamped $($sig.TimeStamperCertificate.NotBefore.ToString('yyyy-MM-dd'))"
            }
            else {
                Ok "signed by $ExpectedSigner"
                Warn "$name carries no RFC 3161 timestamp - this signature will stop verifying when the certificate expires"
            }
        }
        'NotSigned' {
            if ($RequireSignature) {
                Die "$name is NOT SIGNED and this installer requires a signature. See docs/verifying-downloads.md."
            }
            Warn "$name is NOT SIGNED - its origin cannot be verified, only its integrity in transit."
            Warn 'Netherchat releases are not code-signed yet. See docs/release-signing.md.'
        }
        default {
            Die "$name has a signature that did not check out: $($sig.Status).`n       $($sig.StatusMessage)`n       Refusing to install it."
        }
    }
}

function Remove-FromUserPath($dir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -and $userPath -like "*$dir*") {
        $new = ($userPath -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        Ok "removed $dir from user PATH"
    }
}

# ---- uninstall --------------------------------------------------------------
if ($Uninstall) {
    $target = Join-Path $BinDir $Binary
    if (Test-Path $target) {
        Remove-Item $target -Force
        Ok "removed $target"
    }
    else {
        Warn "no $Binary found in $BinDir"
    }
    $serverTarget = Join-Path $BinDir $ServerBinary
    if (Test-Path $serverTarget) {
        Remove-Item $serverTarget -Force
        Ok "removed $serverTarget"
    }
    Remove-FromUserPath $BinDir
    exit 0
}

# ---- platform ---------------------------------------------------------------
Step 'Detecting platform'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { Die "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
Ok "windows/$arch"

# ---- resolve version --------------------------------------------------------
Step 'Resolving release'
if (-not $Version -or $Version -eq 'latest') {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'netherchat-installer' }
    $tag = $rel.tag_name
    if (-not $tag) { Die 'could not resolve the latest release (is the repo published yet?)' }
}
else {
    $tag = 'v' + ($Version -replace '^v', '')
}
$ver = $tag -replace '^v', ''
Ok "netherchat $ver"

# ---- download + verify + install --------------------------------------------
$archive = "netherchat_windows_$arch.zip"
$base = "https://github.com/$Repo/releases/download/$tag"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("netherchat-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Step "Downloading $archive"
    Invoke-WebRequest "$base/$archive" -OutFile (Join-Path $tmp $archive) -UseBasicParsing
    Ok 'downloaded'

    # ---- verify (transfer) --------------------------------------------------
    # FAIL CLOSED. Two of the three outcomes here used to warn and carry on, so
    # an installer for a security product would put an unverified executable on a
    # user's PATH whenever the release page was slow, partial, or hostile — and
    # mention it once, in yellow, in a stream of green ticks.
    #
    # The distinction: a checksum that is PRESENT AND WRONG is evidence of a
    # problem and is always fatal. A checksum that cannot be obtained is an
    # absence of evidence, and that is the only thing -AllowUnverified accepts.
    Step 'Verifying checksum'
    $verified = $false
    $reason = ''
    try {
        Invoke-WebRequest "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt') -UseBasicParsing
        $actual = (Get-FileHash (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLower()
        $line = Select-String -Path (Join-Path $tmp 'checksums.txt') -Pattern ([regex]::Escape($archive)) | Select-Object -First 1
        if ($line) {
            $expected = (($line.Line -split '\s+')[0]).ToLower()
            if ($actual -ne $expected) {
                Die "checksum mismatch for $archive (expected $expected, got $actual) - NOT installing"
            }
            $verified = $true
        }
        else {
            $reason = "release $tag publishes no checksum for $archive"
        }
    }
    catch {
        $reason = "could not fetch $base/checksums.txt"
    }

    if ($verified) {
        Ok 'sha256 verified'
    }
    elseif ($AllowUnverified) {
        Warn "INSTALLING AN UNVERIFIED DOWNLOAD - $reason"
        Warn '-AllowUnverified was given, so this is proceeding without checking the bytes.'
    }
    else {
        Die @"
cannot verify ${archive}: $reason.
       Refusing to install an executable whose integrity was not checked.
       Re-run with -AllowUnverified to accept that deliberately, or fetch the
       release by hand from https://github.com/$Repo/releases/tag/$tag and check
       it yourself. See docs/verifying-downloads.md.
"@
    }

    Step 'Installing'
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    $src = Join-Path $tmp $Binary
    if (-not (Test-Path $src)) { Die "archive did not contain $Binary" }
    Assert-TrustedBinary $src
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item $src (Join-Path $BinDir $Binary) -Force
    Ok "installed to $(Join-Path $BinDir $Binary)"

    # Opt-in relay: the server binary already rode down inside this same archive, so
    # -WithServer installs it with zero extra download. If it is absent (an older
    # release), warn and continue - the client install must always succeed.
    if ($WithServer) {
        $serverSrc = Join-Path $tmp $ServerBinary
        if (Test-Path $serverSrc) {
            Assert-TrustedBinary $serverSrc
            Copy-Item $serverSrc (Join-Path $BinDir $ServerBinary) -Force
            Ok "installed to $(Join-Path $BinDir $ServerBinary)"
        }
        else {
            Warn "this release has no $ServerBinary - the relay was not installed (the client is fine); get it via Docker or 'go build ./cmd/netherchat-server' - see docs/self-hosting.md"
        }
    }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- PATH (user scope) ------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $BinDir), 'User')
    $env:Path += ';' + $BinDir
    Ok "added $BinDir to your user PATH (restart your terminal to pick it up)"
}

Write-Host ''
if ($WithServer) {
    Write-Host "Netherchat $ver installed - client + relay." -ForegroundColor Magenta -NoNewline
    Write-Host '  Messaging that lives below the surface.'
    Write-Host "  Connect:     netherchat connect ws://localhost:3000 --name $env:USERNAME"
    Write-Host '  Run a relay: netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)'
    Write-Host '               Full guide: docs/self-hosting.md'
}
else {
    Write-Host "Netherchat $ver installed - the endpoint client." -ForegroundColor Magenta -NoNewline
    Write-Host '  Messaging that lives below the surface.'
    Write-Host "  Connect:    netherchat connect ws://localhost:3000 --name $env:USERNAME"
    Write-Host '  Self-host:  re-run with -WithServer for the native relay (netherchat-server - already in'
    Write-Host '              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat'
    Write-Host '              Full guide: docs/self-hosting.md'
}
Write-Host ''
