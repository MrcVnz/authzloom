$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = 'python' }

& $python -m unittest discover -s (Join-Path $PSScriptRoot 'tests') -q
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }
& $python -m authzloom.cli plan (Join-Path $PSScriptRoot 'examples\rest.json') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'CLI plan failed' }
& $python -m authzloom.cli plan (Join-Path $PSScriptRoot 'examples\graphql.json') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'GraphQL plan failed' }
& $python -m authzloom.cli plan (Join-Path $PSScriptRoot 'examples\rest.json') --explain | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'CLI plan --explain failed' }

& $python -c @"
import json, os, subprocess, sys
from authzloom.mcp_server import TOOLS
expected = {'authzloom_ingest', 'authzloom_plan', 'authzloom_run', 'authzloom_status', 'authzloom_export'}
assert {tool['name'] for tool in TOOLS} == expected, {tool['name'] for tool in TOOLS}
payload = '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n'
proc = subprocess.run([sys.executable, '-m', 'authzloom.cli', 'mcp'], input=payload, text=True, capture_output=True)
assert proc.returncode == 0, proc.stderr
message = json.loads(proc.stdout.splitlines()[0])
assert {tool['name'] for tool in message['result']['tools']} == expected
"@
if ($LASTEXITCODE -ne 0) { throw 'MCP tool surface failed' }

$forbidden = 'AuthzForge|authzforge|BountyForge|bountyforge|BugBountyWorkspace|HexStrike|durkz|boyzi|targets[/\\]|orchestration[/\\]'
$leaks = Get-ChildItem $PSScriptRoot -Recurse -File |
    Where-Object {
        $_.Name -ne 'verify-integration.ps1' -and
        $_.FullName -notmatch '[/\\](\.venv|\.authzloom|\.soak|build|__pycache__|[^/\\]+\.egg-info)[/\\]'
    } |
    Select-String -Pattern $forbidden
if ($leaks) { throw "Private-workspace reference found: $($leaks.Path | Select-Object -Unique)" }
Write-Host 'PASS: tests, CLI, MCP surface, and privacy scan'
