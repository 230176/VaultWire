$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')

Write-Host "[1/2] Installing backend dependencies..."
Push-Location (Join-Path $Root 'backend')
npm install
Pop-Location

Write-Host "[2/2] Installing frontend dependencies..."
Push-Location (Join-Path $Root 'frontend')
npm install
Pop-Location

Write-Host "Done."
