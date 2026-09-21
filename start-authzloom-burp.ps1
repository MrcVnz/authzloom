$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$dataDir = Join-Path $PSScriptRoot '.authzloom'

if (-not (Test-Path -LiteralPath $python)) { throw 'Run ./setup-env.ps1 first' }
if (-not $env:BURP_JAR -or -not (Test-Path -LiteralPath $env:BURP_JAR)) {
    throw 'Set BURP_JAR to your local Burp Suite JAR'
}
if (-not $env:AUTHZLOOM_TOKEN) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $env:AUTHZLOOM_TOKEN = [Convert]::ToBase64String($bytes)
}

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$tokenFile = Join-Path $dataDir 'runtime-token'
Set-Content -LiteralPath $tokenFile -Value $env:AUTHZLOOM_TOKEN -Encoding ascii -NoNewline
$api = Start-Process -FilePath $python `
    -ArgumentList '-m','authzloom.cli','--data-dir',$dataDir,'serve' `
    -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
try {
    $burp = Start-Process -FilePath 'java' -ArgumentList '-jar',$env:BURP_JAR -PassThru
    $burp.WaitForExit()
} finally {
    Stop-Process -Id $api.Id -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
    Remove-Item Env:AUTHZLOOM_TOKEN -ErrorAction SilentlyContinue
}
