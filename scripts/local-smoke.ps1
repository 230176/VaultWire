$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
if (-not $env:API_URL) { $env:API_URL = 'http://localhost:5000/api/v1' }
Push-Location $Root
node .\scripts\smoke-e2e.mjs
Pop-Location
