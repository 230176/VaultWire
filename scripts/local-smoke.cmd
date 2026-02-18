@echo off
setlocal
if "%API_URL%"=="" set API_URL=http://localhost:5000/api/v1
set ROOT=%~dp0..
pushd "%ROOT%"
node scripts\smoke-e2e.mjs
set ERR=%ERRORLEVEL%
popd
exit /b %ERR%
