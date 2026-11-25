@echo off
REM 离线安全复核 12166 一键运行（仅需 Python 3.12 标准库）
setlocal
cd /d "%~dp0"
python solve.py
set RC=%ERRORLEVEL%
echo.
echo solve.py exited with code %RC%
exit /b %RC%
