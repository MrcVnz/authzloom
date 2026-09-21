param(
    [string]$Python = 'python',
    [switch]$Dev,
    [switch]$Yaml,
    [switch]$Cdp
)

$ErrorActionPreference = 'Stop'
$venv = Join-Path $PSScriptRoot '.venv'

& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 'Python 3.11+ is required')"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required' }
if (-not (Test-Path -LiteralPath $venv)) { & $Python -m venv $venv }

$venvPython = Join-Path $venv 'Scripts\python.exe'
$extras = @()
if ($Dev) { $extras += 'dev' }
if ($Yaml) { $extras += 'yaml' }
if ($Cdp) { $extras += 'cdp' }
$spec = if ($extras.Count) {
    $PSScriptRoot + "[" + ($extras -join ',') + "]"
} else {
    $PSScriptRoot
}

& $venvPython -m pip install --editable $spec
if ($LASTEXITCODE -ne 0) { throw 'AuthzLoom installation failed' }
Write-Host "AuthzLoom environment ready: $venvPython"
