@echo off
setlocal
set "REPO=https://github.com/nickjon11/SFTP_Manager.git"
set "ROOT=%~dp0"
where git >nul 2>&1 || (echo Git is required. & pause & exit /b 1)
if exist "%ROOT%repo_checkout" (echo repo_checkout already exists. Rename or remove it first. & pause & exit /b 1)
git clone "%REPO%" "%ROOT%repo_checkout" || (pause & exit /b 1)
cd /d "%ROOT%repo_checkout"
rem Preserve the existing .github workflow and other repository files.
if exist "SFTP_Manager\app.py" (
  if exist "sftp_manager" (echo Both source folders exist; resolve manually. & pause & exit /b 1)
  ren "SFTP_Manager" "sftp_manager_temp"
  ren "sftp_manager_temp" "sftp_manager"
)
if not exist "sftp_manager" mkdir "sftp_manager"
robocopy "%ROOT%sftp_manager" "%CD%\sftp_manager" /E /NFL /NDL /NJH /NJS >nul
copy /Y "%ROOT%main.py" "main.py" >nul
copy /Y "%ROOT%requirements.txt" "requirements.txt" >nul
copy /Y "%ROOT%README.md" "README.md" >nul
copy /Y "%ROOT%RELEASE_NOTES_v0.8.2.md" "RELEASE_NOTES_v0.8.2.md" >nul
python -m compileall -q main.py sftp_manager || (echo Python syntax check failed. & pause & exit /b 1)
git add -A
git status --short
choice /M "Commit and push these changes to main"
if errorlevel 2 exit /b 0
git commit -m "Release SFTP Manager v0.8.2" || (pause & exit /b 1)
git push origin main || (pause & exit /b 1)
echo Push completed. Check GitHub Actions before tagging a release.
pause
