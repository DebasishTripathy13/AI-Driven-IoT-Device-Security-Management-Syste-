#!/usr/bin/env python3
"""
Server Launcher Script
Starts all required servers for the Medical IoT Device Management System
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def start_server_in_new_window(server_name, script_name, port):
    """Start a server in a new command prompt window"""
    try:
        cmd = f'start "Medical IoT - {server_name}" cmd /k "python {script_name}"'
        subprocess.run(cmd, shell=True, cwd=Path(__file__).parent)
        print(f"✓ {server_name} starting on port {port}...")
        return True
    except Exception as e:
        print(f"✗ Failed to start {server_name}: {e}")
        return False

def check_port_available(port):
    """Check if a port is available"""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except:
        return False

def main():
    print("=" * 60)
    print("🏥 Medical IoT Device Management System")
    print("🚀 Server Launcher")
    print("=" * 60)
    print()
    
    # Check if required files exist
    required_files = [
        "api_server.py",
        "ai_security_service.py", 
        "dashboard_server.py"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    print("📋 Starting servers in order...")
    print()
    
    # Start AI Security Service first (port 8002)
    print("1️⃣ Starting AI Security Service...")
    if start_server_in_new_window("AI Security Service", "ai_security_service.py", 8002):
        time.sleep(3)  # Wait for AI service to initialize
    else:
        print("❌ Failed to start AI Security Service")
        return False
    
    # Start API Server (port 8001)
    print("2️⃣ Starting API Server...")
    if start_server_in_new_window("API Server", "api_server.py", 8001):
        time.sleep(3)  # Wait for API server to initialize
    else:
        print("❌ Failed to start API Server")
        return False
    
    # Start Dashboard Server (port 8004)
    print("3️⃣ Starting Security Test Dashboard...")
    if start_server_in_new_window("Security Dashboard", "dashboard_server.py --port 8004", 8004):
        time.sleep(2)
    else:
        print("❌ Failed to start Security Dashboard")
        return False
    
    # Start Web Server (port 8000)
    if os.path.exists("main.py"):
        print("4️⃣ Starting Web Server...")
        if start_server_in_new_window("Web Server", "main.py", 8000):
            time.sleep(2)
        else:
            print("❌ Failed to start Web Server")
    
    print()
    print("=" * 60)
    print("🎉 All servers are starting up!")
    print("=" * 60)
    print()
    print("🌐 Access Points:")
    print("   • 🔒 AI Security Service:    http://127.0.0.1:8002/health")
    print("   • 🖥️  API Server:            http://127.0.0.1:8001/docs")
    print("   • 🛡️ Security Dashboard:     http://127.0.0.1:8004/ai_security_test_dashboard.html")
    if os.path.exists("main.py"):
        print("   • 🌐 Device Manager:        http://127.0.0.1:8000")
    print()
    print("📊 AI Security Testing:")
    print("   • Use the Security Dashboard to manually test malicious code")
    print("   • Test different IP addresses and attack vectors")
    print("   • View real-time AI analysis results")
    print()
    print("🔧 Server Status:")
    print("   • Each server runs in its own window")
    print("   • Close individual windows to stop specific servers")
    print("   • Check server logs in their respective windows")
    print()
    print("Press Enter to exit launcher (servers will continue running)...")
    input()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("🚀 Server launch completed!")
        else:
            print("❌ Server launch failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Launch cancelled by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)