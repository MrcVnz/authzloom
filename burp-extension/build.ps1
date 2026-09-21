$ErrorActionPreference = 'Stop'
$classes = Join-Path $PSScriptRoot 'build\classes'
$output = Join-Path $PSScriptRoot 'build\authzloom-burp.jar'

if (-not $env:BURP_JAR -or -not (Test-Path -LiteralPath $env:BURP_JAR)) {
    throw 'Set BURP_JAR to your local Burp Suite JAR'
}
if (Test-Path -LiteralPath $classes) { Remove-Item -LiteralPath $classes -Recurse -Force }
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$sources = Get-ChildItem (Join-Path $PSScriptRoot 'src\main\java') -Recurse -Filter '*.java' |
    ForEach-Object FullName
& javac --release 21 -implicit:none -cp $env:BURP_JAR -d $classes $sources
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }
& jar --create --file $output -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'jar failed' }
Write-Host "Built $output"
