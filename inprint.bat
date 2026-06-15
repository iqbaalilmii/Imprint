@echo off
cd /d "%~dp0"
echo Membuka Imprint Forensics...
PowerShell -NoProfile -ExecutionPolicy Bypass -File "inprint.ps1"
echo.
echo Jika tulisan ini terlihat, berarti server telah berhenti atau ada error.
pause
