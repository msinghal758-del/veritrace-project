@echo off
title VeriTrace - AI Cyber Incident Response System
color 0B
echo =====================================================================
echo           VeriTrace: AI-Powered Cyber Incident Response
echo =====================================================================
echo.
echo [1/3] Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not available in PATH.
    echo Please install Python 3.10+ and add it to your system PATH.
    pause
    exit /b 1
)

echo [2/3] Opening VeriTrace Incident Console in your default browser...
start "" http://127.0.0.1:8000/app

echo [3/3] Starting Uvicorn ASGI Server on http://127.0.0.1:8000 ...
echo [INFO] Swagger API Docs available at: http://127.0.0.1:8000/docs
echo [INFO] Press Ctrl+C to stop the server.
echo.
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
pause
