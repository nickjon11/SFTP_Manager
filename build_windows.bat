@echo off
setlocal
cd /d "%~dp0"
echo =============================================
echo   SFTP Manager v0.8.0 - Windows EXE Builder
echo   Recommended Python version: 3.13 x64
echo =============================================
where py >nul 2>&1
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.13 from python.org.
  goto fail
)
py -3.13 --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.13 is required. Install Python 3.13 x64.
  goto fail
)
if not exist ".venv313\Scripts\python.exe" (
  py -3.13 -m venv .venv313
  if errorlevel 1 goto fail
)
".venv313\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto fail
".venv313\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
".venv313\Scripts\python.exe" -m pip install --upgrade pyinstaller-hooks-contrib
if errorlevel 1 goto fail
".venv313\Scripts\python.exe" -c "import cryptography.hazmat.bindings._rust; print('Cryptography OK')"
if errorlevel 1 goto fail
echo Building EXE (one-folder format for reliable DLL loading)...
".venv313\Scripts\python.exe" -m PyInstaller --clean --noconfirm --onedir --windowed --name "SFTP Manager" --icon "sftp_manager\assets\app.ico" --add-data "sftp_manager\assets;sftp_manager/assets" --collect-all cryptography --collect-all cffi --collect-all paramiko main.py
if errorlevel 1 goto fail
echo.
echo SUCCESS! Open dist\SFTP Manager\SFTP Manager.exe
echo Keep the _internal folder alongside the EXE.
explorer "dist\SFTP Manager"
pause
exit /b 0
:fail
echo.
echo Build failed. Copy the errors above for troubleshooting.
pause
exit /b 1
