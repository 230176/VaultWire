$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location (Join-Path $Root 'frontend')
npm run dev
Pop-Location
