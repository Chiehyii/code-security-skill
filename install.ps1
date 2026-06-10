# Code Security Skill — Windows PowerShell installer
#
# Usage (run from your project root in PowerShell):
#
#   irm https://raw.githubusercontent.com/YOUR_ORG/code-security-skill/main/install.ps1 | iex
#
# To pass flags, use the script block form:
#
#   & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/YOUR_ORG/code-security-skill/main/install.ps1'))) -ai claude
#   & ([scriptblock]::Create((irm '...'))) -ai cursor,copilot -force
#
# Requires: git, python3

param(
    [string[]] $ai    = @("all"),
    [switch]   $force
)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/YOUR_ORG/code-security-skill"
$TmpDir  = Join-Path $env:TEMP "code-security-skill-$(Get-Random)"

try {
    Write-Host ""
    Write-Host "  Shield  Code Security Skill — Downloading..."
    git clone --depth 1 --quiet $RepoUrl $TmpDir

    Write-Host "  Shield  Installing into $(Get-Location) ..."

    $extraArgs = @()
    if ($ai)    { $extraArgs += "--ai";    $extraArgs += $ai }
    if ($force) { $extraArgs += "--force" }

    python3 "$TmpDir\scripts\install_skill.py" . @extraArgs
}
finally {
    if (Test-Path $TmpDir) { Remove-Item -Recurse -Force $TmpDir }
}
