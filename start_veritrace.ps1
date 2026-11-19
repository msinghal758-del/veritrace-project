# VeriTrace One-Click Startup Script (PowerShell)
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "       VeriTrace: AI-Powered Cyber Incident Response System          " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Verifying Python runtime..." -ForegroundColor Yellow
python --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Python is not installed or not in system PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[2/3] Launching Web Interface..." -ForegroundColor Yellow
Start-Process "http://127.0.0.1:8000/app"

Write-Host "[3/3] Starting FastAPI Uvicorn ASGI Server on http://127.0.0.1:8000 ..." -ForegroundColor Yellow
Write-Host "      - Web App:      http://127.0.0.1:8000/app" -ForegroundColor Cyan
Write-Host "      - Swagger Docs: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "      - Metrics API:  http://127.0.0.1:8000/api/ml/metrics" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to shut down the server." -ForegroundColor Gray

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
