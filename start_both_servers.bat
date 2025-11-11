@echo off
echo ========================================
echo  Medical IoT Device Management System
echo ========================================
echo.
echo Starting servers...
echo.

REM Start API Server
echo [1/2] Starting API Server on port 8001...
start "API Server" cmd /k "cd /d %~dp0 && python api_server.py"
timeout /t 3 /nobreak >nul

REM Start Web Server  
echo [2/2] Starting Web Server on port 8080...
start "Web Server" cmd /k "cd /d %~dp0 && python start_web_server.py"
timeout /t 2 /nobreak >nul

echo.
echo [SUCCESS] Both servers are starting up!
echo.
echo Access Points:
echo   - Web Interface: http://localhost:8080
echo   - Admin Dashboard: http://localhost:8001/admin
echo   - API Documentation: http://localhost:8001/docs
echo.
echo Note: 
echo   - API Server runs on port 8001
echo   - Web Server runs on port 8080 (changed from 8000 to avoid conflicts)
echo   - Both servers are running in separate windows
echo.
pause