@echo off
echo 🚀 Starting Medical IoT CVE System with OSV Integration
echo.

REM Start API Server (port 8001)
echo Starting API Server on port 8001...
start "API Server" python -c "import uvicorn; from api_server import app; uvicorn.run(app, host='0.0.0.0', port=8001, reload=False)"

REM Wait a moment
timeout /t 3 /nobreak > nul

REM Start Web Server (port 8000) 
echo Starting Web Server on port 8000...
start "Web Server" python -c "import uvicorn; from main import app; uvicorn.run(app, host='0.0.0.0', port=8000, reload=False)"

echo.
echo ✅ Servers started! Access points:
echo   • CVE Notification Board: http://127.0.0.1:8000/cve-notification-board
echo   • Main Dashboard: http://127.0.0.1:8000
echo   • API Documentation: http://127.0.0.1:8001/docs
echo.
echo 🔍 Features:
echo   • Real CVE data from OSV (Open Source Vulnerabilities)
echo   • ML-powered update scheduling
echo   • Professional medical IoT interface
echo   • Interactive vulnerability details
echo.
pause