@echo off
echo Starting Medical IoT Device Management System
echo ============================================
echo.

echo Starting API Server on port 8001...
start "API Server" python api_server.py

echo Waiting for API server to start...
timeout /t 3 /nobreak > nul

echo Starting Web Server on port 8000...
start "Web Server" python main.py

echo.
echo System started successfully!
echo.
echo Web Interface: http://localhost:8000
echo API Documentation: http://localhost:8001/docs
echo.
echo Press any key to exit...