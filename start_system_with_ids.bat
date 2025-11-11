@echo off
echo ========================================================
echo       Medical IoT System with IDS Security
echo ========================================================
echo.

echo 🔍 Checking system requirements...

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.12 or higher.
    pause
    exit /b 1
)

echo ✅ Python is available

REM Check if virtual environment exists
if not exist venv\ (
    echo 📦 Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

REM Install/update dependencies
echo 📦 Installing dependencies...
pip install -r requirements.txt --quiet

REM Check if devices are registered
if not exist output\devices.json (
    echo 🏥 Registering medical devices...
    python register_iothub_devices.py --count 10
    if errorlevel 1 (
        echo ❌ Failed to register devices. Check your .env file.
        pause
        exit /b 1
    )
)

echo.
echo 🛡️ Starting Medical IoT System with IDS Protection...
echo.
echo 📊 System Components:
echo   • API Server (Port 8001) - Device management with IDS protection
echo   • Web Server (Port 8000) - User interface and proxy
echo   • IDS System - Real-time threat detection and blocking
echo   • Admin Dashboard - Security monitoring and management
echo.

echo 🚀 Starting API Server with IDS protection...
start "Medical IoT API Server + IDS" python api_server.py

echo ⏳ Waiting for API server to initialize...
timeout /t 5 /nobreak > nul

echo 🌐 Starting Web Server...
start "Medical IoT Web Server" python main.py

echo ⏳ Waiting for web server to initialize...
timeout /t 3 /nobreak > nul

echo.
echo ✅ System Started Successfully!
echo.
echo 🌐 Access Points:
echo   Web Interface:     http://localhost:8000
echo   Admin Dashboard:   http://localhost:8001/admin
echo   API Documentation: http://localhost:8001/docs
echo.
echo 🛡️ IDS Features:
echo   • SQL Injection Detection
echo   • Code/Command Injection Prevention  
echo   • XSS Attack Protection
echo   • Flood Detection (>1000 req/min blocks IP)
echo   • Suspicious User Agent Detection
echo   • Unauthorized Access Monitoring
echo   • Real-time IP Blocking
echo   • Comprehensive Security Logging
echo.
echo 🧪 Security Testing:
echo   Run: python test_ids_security.py
echo.
echo 📊 Log Files:
echo   • api_server.log        - API server activity
echo   • web_server.log        - Web server activity  
echo   • ids_security.log      - Security events and threats
echo   • middleware.log        - Request processing logs
echo.
echo Press any key to exit startup script (servers will continue running)...
pause > nul