@echo off
title PhishNet
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator rights for firewall control...
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
python -m pip install -r requirements.txt
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:5000"
python app.py
pause
