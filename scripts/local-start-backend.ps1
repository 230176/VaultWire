$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location (Join-Path $Root 'backend')
npm run dev
Pop-Location
