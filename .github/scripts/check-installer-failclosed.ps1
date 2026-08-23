#Requires -Version 5.1
<#
.SYNOPSIS
    Run installer/install.ps1 end to end and prove it refuses what it cannot verify.

.DESCRIPTION
    The Windows twin of check-installer-failclosed.sh, and it checks one thing the
    POSIX installer cannot: the Authenticode signature. install.ps1 is the only
    installer that runs on the platform this whole phase exists for, so it is the
    one that gets to ask "is this binary from Astralis" rather than only "did the
    bytes arrive intact".

    It starts where a user starts — `install.ps1 -Version … -BinDir …` against a
    release it fetches — and asserts on whether a binary ended up on disk.

    Fixtures are served over file:// rather than https://. Invoke-WebRequest
    handles both, and the branch under test is the installer's, not .NET's; what
    this does NOT cover is TLS behaviour, which is stated rather than implied.

    The signing fixtures are made with New-SelfSignedCertificate into
    Cert:\CurrentUser\My and removed again in the finally block. Nothing is
    written to a machine store and nothing is installed as trusted.

.PARAMETER PayloadExe
    A real PE to put in the fixture archives. Defaults to building
    ./cmd/netherchat-identity, the smallest of the three shipped Windows binaries.
#>
[CmdletBinding()]
param([string]$PayloadExe = "")

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$src = Join-Path $root 'installer\install.ps1'
if (-not (Test-Path $src)) { Write-Host "::error::$src not found"; exit 1 }

$fails = 0
function Report($ok, $msg) {
    if ($ok) { Write-Host "  ok    $msg" }
    else { Write-Host "::error::$msg"; $script:fails++ }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("nc-installer-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

# install.ps1 edits the USER PATH. A test must not leave that behind.
$pathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')
$testCerts = @()

try {
    # ---- the installer under test, pointed at a local release ---------------
    $sut = Join-Path $work 'install-under-test.ps1'
    $content = Get-Content $src -Raw
    $needle = '$base = "https://github.com/$Repo/releases/download/$tag"'
    if (-not $content.Contains($needle)) {
        Write-Host "::error::could not find the release-URL line in $src - this test is reading a shape that no longer exists"
        exit 1
    }
    $content.Replace($needle, '$base = $env:NC_TEST_BASE') | Set-Content -Path $sut -Encoding UTF8

    # ---- a real PE to ship --------------------------------------------------
    if (-not $PayloadExe) {
        $PayloadExe = Join-Path $work 'netherchat-identity.exe'
        Push-Location $root
        try {
            $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
            & go build -trimpath -o $PayloadExe ./cmd/netherchat-identity
            if ($LASTEXITCODE -ne 0) { throw "go build failed" }
        } finally { Pop-Location; Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue }
    }
    if (-not (Test-Path $PayloadExe)) { Write-Host "::error::payload not found: $PayloadExe"; exit 1 }

    $serve = Join-Path $work 'serve'
    New-Item -ItemType Directory -Path $serve -Force | Out-Null
    $env:NC_TEST_BASE = 'file:///' + ($serve -replace '\\', '/')
    $archive = 'netherchat_windows_amd64.zip'

    # Build a zip whose netherchat.exe is $exe, and write checksums.txt per $mode.
    function Set-Fixture([string]$exe, [string]$mode) {
        $stage = Join-Path $work 'stage'
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        Copy-Item $exe (Join-Path $stage 'netherchat.exe')
        Copy-Item $exe (Join-Path $stage 'netherchat-server.exe')
        $zip = Join-Path $serve $archive
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
        $sum = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
        $cs = Join-Path $serve 'checksums.txt'
        Remove-Item $cs -Force -ErrorAction SilentlyContinue
        switch ($mode) {
            'good' { "$sum  $archive" | Set-Content $cs -Encoding ASCII }
            'none' { }
            'noentry' { "$sum  netherchat_someotherthing.zip" | Set-Content $cs -Encoding ASCII }
            'mismatch' { ("0" * 64) + "  $archive" | Set-Content $cs -Encoding ASCII }
        }
    }

    # Run the installer. Returns @{ rc; installed; out }
    #
    # NOTE ON CASE LABELS. $label ends up inside -BinDir, which the installer
    # echoes, so a label is part of the text every assertion below searches. A
    # case called "G1-unsigned" satisfied `-match 'unsigned'` from its own
    # directory name while install.ps1 said nothing about signatures at all.
    # Labels here must not contain a word any assertion looks for.
    function Invoke-Sut([string]$label, [string[]]$extra) {
        $bindir = Join-Path $work "bin-$label"
        Remove-Item $bindir -Recurse -Force -ErrorAction SilentlyContinue
        $outFile = Join-Path $work "out-$label.txt"
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $sut,
            '-Version', '9.9.9', '-BinDir', $bindir) + $extra
        # A refusal is the expected outcome of half the cases here, and a refusal
        # writes to stderr. With ErrorActionPreference=Stop that surfaces as a
        # NativeCommandError and takes the harness down with it, so the exit code
        # of the thing under test is read rather than thrown.
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & powershell.exe @args *> $outFile } finally { $ErrorActionPreference = $prev }
        $rc = $LASTEXITCODE
        [pscustomobject]@{
            rc        = $rc
            installed = (Test-Path (Join-Path $bindir 'netherchat.exe'))
            out       = (Get-Content $outFile -Raw)
        }
    }

    function Assert-Case([string]$label, [string]$expect, [string[]]$extra = @()) {
        $r = Invoke-Sut $label $extra
        if ($expect -eq 'install') {
            $ok = ($r.rc -eq 0 -and $r.installed)
            Report $ok "$label`: expected install - rc=$($r.rc) installed=$($r.installed)"
        }
        else {
            $ok = ($r.rc -ne 0 -and -not $r.installed)
            Report $ok "$label`: expected refusal - rc=$($r.rc) installed=$($r.installed)"
        }
        if (-not $ok) { $r.out -split "`n" | ForEach-Object { Write-Host "        $_" } }
        return $r
    }

    Write-Host "installer fail-closed (install.ps1):"

    # ---- checksum behaviour, unsigned payload --------------------------------
    Set-Fixture $PayloadExe 'good'
    $r = Assert-Case 'A-verified' 'install'
    Report ($r.installed -and $r.out -match 'sha256 verified') "A-verified: printed 'sha256 verified'"

    Set-Fixture $PayloadExe 'none'
    Assert-Case 'B-no-checksums-file' 'refuse' | Out-Null

    Set-Fixture $PayloadExe 'noentry'
    Assert-Case 'C-no-entry' 'refuse' | Out-Null

    Set-Fixture $PayloadExe 'mismatch'
    Assert-Case 'D-mismatch' 'refuse' | Out-Null

    Set-Fixture $PayloadExe 'none'
    $r = Assert-Case 'F-optout' 'install' @('-AllowUnverified')
    Report ($r.installed -and $r.out -match '(?i)unverified download') `
        "F-optout: warned about what it skipped"

    # ---- Authenticode behaviour ---------------------------------------------
    # G1: no signature at all. Until the certificate exists this is every release,
    # so it must install - but it must say the origin is unproven.
    Set-Fixture $PayloadExe 'good'
    $r = Assert-Case 'G1-nosig' 'install'
    Report ($r.installed -and $r.out -match '(?i)not signed') `
        "G1-nosig: said the binary is unsigned"

    # G2: signed by someone who is not Astralis. This is the counterfeit case, and
    # it is the reason the installer checks a signature at all rather than only a
    # checksum: a checksum published next to a hostile download matches it.
    $cert = New-SelfSignedCertificate -Subject "CN=Definitely Not Astralis" `
        -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddDays(1)
    $testCerts += $cert
    $signedExe = Join-Path $work 'signed.exe'
    Copy-Item $PayloadExe $signedExe
    $null = Set-AuthenticodeSignature -FilePath $signedExe -Certificate $cert
    $st = (Get-AuthenticodeSignature $signedExe).Status
    if ($st -eq 'NotSigned') {
        Report $false "G2 fixture: Set-AuthenticodeSignature produced no signature - the case below would prove nothing"
    }
    else {
        Set-Fixture $signedExe 'good'
        Assert-Case 'G2-foreign-signer' 'refuse' | Out-Null
    }

    # G3: signed and then modified. Get-AuthenticodeSignature reports HashMismatch;
    # the checksum in the release would also catch this, which is the point - these
    # are two independent checks and the installer should not need either to be the
    # only one.
    $tampered = Join-Path $work 'tampered.exe'
    Copy-Item $signedExe $tampered
    $fs = [System.IO.File]::Open($tampered, 'Open', 'ReadWrite')
    try { $fs.Seek(4096, 'Begin') | Out-Null; $fs.WriteByte(0x90); $fs.WriteByte(0x90) } finally { $fs.Close() }
    $stT = (Get-AuthenticodeSignature $tampered).Status
    if ($stT -eq $st) {
        Report $false "G3 fixture: tampering did not change the signature status ($stT) - the case below would prove nothing"
    }
    else {
        Set-Fixture $tampered 'good'
        Assert-Case 'G3-tampered' 'refuse' | Out-Null
    }
}
finally {
    [Environment]::SetEnvironmentVariable('Path', $pathBefore, 'User')
    foreach ($c in $testCerts) {
        Remove-Item ("Cert:\CurrentUser\My\" + $c.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:NC_TEST_BASE -ErrorAction SilentlyContinue
}

Write-Host ""
if ($fails -ne 0) {
    Write-Host "::error::installer fail-closed (ps1): $fails check(s) failed"
    exit 1
}
Write-Host "installer fail-closed (ps1): all checks passed"
# EXIT EXPLICITLY. Most cases here run install.ps1 expecting it to REFUSE, so the
# last external process this script runs exits 1 on purpose. Without this line the
# script's own status is whatever that was: GitHub invokes it as
# `powershell -command ". '{0}'"`, which carries $LASTEXITCODE out as the step's
# verdict, so a run in which every check passed reported failure. It passed when
# run by hand, where nothing reads the status. Same shape as osslsigncode verify
# returning 0 on an untimestamped signature -- an exit code that does not mean
# what the caller assumes.
exit 0
