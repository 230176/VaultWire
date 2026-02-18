$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $Root
docker compose up --build -d
docker compose ps
Write-Host "Frontend: http://localhost:5173"
Write-Host "Backend Health: http://localhost:5000/api/v1/health"
Pop-Location
