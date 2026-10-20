# Install the latest Windows release for the current user. No administrator rights.
# Default repository is rxznik/rust-vpn. RUSTVPN_REPO overrides it
# (owner/name or a github.com URL). Replaces binaries on a later run.
# Does not read or write state.db or any app data directory.

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    [Console]::Error.WriteLine($Message)
    exit 1
}

$repo = $env:RUSTVPN_REPO
if ([string]::IsNullOrWhiteSpace($repo)) {
    $repo = "rxznik/rust-vpn"
}
$repo = $repo.Trim()
$repo = $repo -replace '\.git$', ''
$repo = $repo -replace '^https?://github\.com/', ''
$repo = $repo -replace '^git@github\.com:', ''
if ($repo -notmatch '^[^/\s]+/[^/\s]+$') {
    Fail "RUSTVPN_REPO must look like owner/name."
}
$env:RUSTVPN_REPO = $repo

$rawArch = $env:PROCESSOR_ARCHITECTURE
if ($rawArch -eq "x86" -and -not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
    $rawArch = $env:PROCESSOR_ARCHITEW6432
}
switch ($rawArch) {
    "AMD64" { $arch = "x86_64" }
    "ARM64" {
        Fail "This release does not publish rustvpn-windows-aarch64.zip. Only rustvpn-windows-x86_64.zip is built."
    }
    default { Fail "unsupported architecture: $rawArch" }
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Fail "LOCALAPPDATA is unset."
}

$dest = Join-Path $env:LOCALAPPDATA "rustvpn"

$asset = "rustvpn-windows-$arch.zip"
$url = "https://github.com/$($env:RUSTVPN_REPO)/releases/latest/download/$asset"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rustvpn-install-" + [guid]::NewGuid().ToString("n"))
$extract = Join-Path $tmp "extract"
$archiveHasIco = $false

New-Item -ItemType Directory -Force -Path $extract | Out-Null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $zip = Join-Path $tmp $asset
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

    foreach ($name in @("rustvpn.exe", "xray.exe")) {
        $found = Join-Path $extract $name
        if (-not (Test-Path -LiteralPath $found -PathType Leaf)) {
            Fail "archive is missing $name"
        }
    }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -LiteralPath (Join-Path $extract "rustvpn.exe") -Destination (Join-Path $dest "rustvpn.exe") -Force
    Copy-Item -LiteralPath (Join-Path $extract "xray.exe") -Destination (Join-Path $dest "xray.exe") -Force

    $icoSrc = Join-Path $extract "rustvpn.ico"
    if (Test-Path -LiteralPath $icoSrc -PathType Leaf) {
        Copy-Item -LiteralPath $icoSrc -Destination (Join-Path $dest "rustvpn.ico") -Force
        $archiveHasIco = $true
    }
} finally {
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($null -eq $userPath) {
    $userPath = ""
}
$normalizedDest = $dest.TrimEnd('\')
$present = $false
foreach ($entry in ($userPath -split ';')) {
    if ([string]::IsNullOrWhiteSpace($entry)) {
        continue
    }
    $normalized = $entry.Trim().TrimEnd('\')
    if ($normalized.Equals($normalizedDest, [System.StringComparison]::OrdinalIgnoreCase)) {
        $present = $true
        break
    }
}
if (-not $present) {
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        $updated = $dest
    } else {
        $updated = "$userPath;$dest"
    }
    [Environment]::SetEnvironmentVariable("Path", $updated, "User")
}

$desktop = [Environment]::GetFolderPath("Desktop")
if ([string]::IsNullOrWhiteSpace($desktop)) {
    Fail "could not resolve the user desktop folder."
}
$shortcutPath = Join-Path $desktop "rustvpn.lnk"
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $dest "rustvpn.exe"
$shortcut.WorkingDirectory = $dest
if ($archiveHasIco) {
    $shortcut.IconLocation = "$(Join-Path $dest 'rustvpn.ico'),0"
} else {
    $shortcut.IconLocation = "$($shortcut.TargetPath),0"
}
$shortcut.Save()

Write-Host "Installed rustvpn and xray to $dest"
