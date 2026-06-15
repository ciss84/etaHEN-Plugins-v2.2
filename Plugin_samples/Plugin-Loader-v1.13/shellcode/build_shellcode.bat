@echo off
echo ==========================================
echo  PS5 Shellcode Builder (via WSL)
echo ==========================================

for /f "delims=" %%i in ('wsl wslpath -u "%~dp0build_shellcode.sh"') do set SH_PATH=%%i
wsl bash "%SH_PATH%"

pause