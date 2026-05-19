<#
Jianlai user-level installer for Windows PowerShell.

One-line install after publishing:
  irm https://raw.githubusercontent.com/Lniosy/jianlai/master/scripts/install.ps1 | iex

Optional environment variables:
  JIANLAI_REPO_URL   Git repository URL. Default: https://github.com/Lniosy/jianlai.git
  JIANLAI_BRANCH     Git branch/ref. Default: master
  JIANLAI_INSTALL_DIR Install root. Default: %LOCALAPPDATA%\jianlai
#>
$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:JIANLAI_REPO_URL) { $env:JIANLAI_REPO_URL } else { "https://github.com/Lniosy/jianlai.git" }
$Branch = if ($env:JIANLAI_BRANCH) { $env:JIANLAI_BRANCH } else { "master" }
$InstallRoot = if ($env:JIANLAI_INSTALL_DIR) { $env:JIANLAI_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "jianlai" }
$AppDir = Join-Path $InstallRoot "app"
$VenvDir = Join-Path $InstallRoot ".venv"
$BinDir = Join-Path $InstallRoot "bin"
$ConfigDir = Join-Path $HOME ".jianlai"
$ConfigFile = Join-Path $ConfigDir ".env"

function Write-Step($Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-Command($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-Python312Command {
    if (Test-Command "py") {
        try {
            $out = & py -3.12 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out -eq "3.12") { return @("py", "-3.12") }
        } catch {}
    }
    if (Test-Command "python") {
        try {
            $out = & python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out -eq "3.12") { return @("python") }
        } catch {}
    }
    throw "Python 3.12 not found. Install Python 3.12 first, then rerun this installer."
}

function Invoke-Python($PyCmd, [string[]]$ArgsList) {
    $exe = $PyCmd[0]
    $prefixArgs = @()
    if ($PyCmd.Count -gt 1) { $prefixArgs = $PyCmd[1..($PyCmd.Count - 1)] }
    & $exe @prefixArgs @ArgsList
    if ($LASTEXITCODE -ne 0) { throw "Python command failed: $exe $($prefixArgs -join ' ') $($ArgsList -join ' ')" }
}

Write-Step "Preparing directories"
New-Item -ItemType Directory -Force -Path $InstallRoot, $BinDir, $ConfigDir | Out-Null

if (-not (Test-Command "git")) {
    throw "Git not found. Install Git first, then rerun this installer."
}

Write-Step "Fetching Jianlai source"
if (Test-Path (Join-Path $AppDir ".git")) {
    git -C $AppDir fetch --all --prune
    git -C $AppDir checkout $Branch
    git -C $AppDir pull --ff-only origin $Branch
} else {
    if (Test-Path $AppDir) { Remove-Item -LiteralPath $AppDir -Recurse -Force }
    git clone --branch $Branch $RepoUrl $AppDir
}
if ($LASTEXITCODE -ne 0) { throw "Git operation failed." }

$SkillsDir = Join-Path $AppDir "references\hack-skills"
Write-Step "Fetching hack-skills knowledge base"
if (Test-Path (Join-Path $SkillsDir ".git")) {
    git -C $SkillsDir pull --ff-only
} else {
    New-Item -ItemType Directory -Force -Path (Split-Path $SkillsDir -Parent) | Out-Null
    git clone --depth 1 https://github.com/yaklang/hack-skills.git $SkillsDir
}
if ($LASTEXITCODE -ne 0) { throw "Failed to fetch hack-skills." }

$PyCmd = @(Get-Python312Command)
Write-Step "Using Python: $($PyCmd -join ' ')"
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    Invoke-Python $PyCmd @("-m", "venv", $VenvDir)
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
Write-Step "Installing Jianlai into isolated venv"
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $VenvPython -m pip install -e $AppDir
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

if (-not (Test-Path $ConfigFile)) {
    Write-Step "Creating user config: $ConfigFile"
    $DbPath = (Join-Path $ConfigDir "data\jianlai.db").Replace("\", "/")
    @"
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_PRO_MODEL=deepseek-v4-pro
DEEPSEEK_FLASH_MODEL=deepseek-v4-flash

DATABASE_PATH=$DbPath
MAX_CONCURRENT_TASKS=5
LOG_LEVEL=INFO
"@ | Set-Content -LiteralPath $ConfigFile -Encoding UTF8
}

Write-Step "Creating global jianlai launcher"
$Launcher = Join-Path $BinDir "jianlai.cmd"
$JianlaiExe = (Join-Path $VenvDir "Scripts\jianlai.exe")
@"
@echo off
set "JIANLAI_HOME=$ConfigDir"
"$JianlaiExe" %*
"@ | Set-Content -LiteralPath $Launcher -Encoding ASCII

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathItems = @()
if ($UserPath) { $PathItems = $UserPath -split ";" | Where-Object { $_ } }
$AlreadyInPath = $false
foreach ($item in $PathItems) {
    if ($item.TrimEnd("\") -ieq $BinDir.TrimEnd("\")) { $AlreadyInPath = $true; break }
}
if (-not $AlreadyInPath) {
    Write-Step "Adding Jianlai bin directory to user PATH"
    $NewPath = if ($UserPath) { "$BinDir;$UserPath" } else { $BinDir }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    $env:Path = "$BinDir;$env:Path"
}

Write-Host ""
Write-Host "Jianlai installed successfully." -ForegroundColor Green
Write-Host "Config file: $ConfigFile"
Write-Host "Launcher:    $Launcher"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit config and set DEEPSEEK_API_KEY: notepad `"$ConfigFile`""
Write-Host "  2. Open a new PowerShell window, then run: jianlai"
Write-Host ""
