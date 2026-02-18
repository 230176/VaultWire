@echo off
setlocal
set ROOT=%~dp0..
pushd "%ROOT%\backend"
call npm install || exit /b 1
popd
pushd "%ROOT%\frontend"
call npm install || exit /b 1
popd
echo Done.
