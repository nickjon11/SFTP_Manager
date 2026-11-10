@echo off
setlocal
cd /d "%~dp0"
title SFTP Manager v0.8.2
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto error
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto error
".venv\Scripts\python.exe" main.py
if errorlevel 1 goto error
exit /b 0
:error
echo SFTP Manager exited with an error.
pause
exit /b 1
