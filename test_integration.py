# Simple integration test for AI security
import requests
import json

def test_legitimate_request():
    """Test a legitimate request that should be approved"""
    print("🧪 Testing legitimate request...")
    
    payload = {
        "deviceId": "med-ecg-001",
        "code": "print('Hello World')",
        "language": "python",
        "parameters": {}
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ GOOD: Legitimate request was approved!")
            result = response.json()
            print(f"Response: {result.get('message', 'No message')}")
        elif response.status_code == 403:
            print("❌ BAD: Legitimate request was blocked!")
            print(f"Error: {response.text}")
        elif response.status_code == 500:
            print("🔧 SERVER ERROR: Internal server error")
            print(f"Error: {response.text}")
        else:
            print(f"🤔 Unexpected status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def test_malicious_request():
    """Test a malicious request that should be blocked"""
    print("\n🧪 Testing malicious request...")
    
    payload = {
        "deviceId": "med-ecg-001",
        "code": "import os; os.system('rm -rf /')",
        "language": "python", 
        "parameters": {}
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 403:
            print("✅ GOOD: Malicious request was blocked!")
            try:
                error_detail = response.json()
                print(f"Block reason: {error_detail.get('detail', {}).get('reasons', ['No reason provided'])}")
            except:
                print(f"Block response: {response.text}")
        elif response.status_code == 200:
            print("❌ CRITICAL: Malicious request was allowed!")
            print(f"Response: {response.text}")
        elif response.status_code == 500:
            print("🔧 SERVER ERROR: Internal server error")
            print(f"Error: {response.text}")
        else:
            print(f"🤔 Unexpected status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

if __name__ == "__main__":
    print("🛡️ AI Security Integration Test")
    print("=" * 50)
    
    # Check if AI security service is running
    try:
        health_response = requests.get("http://127.0.0.1:8002/health", timeout=5)
        if health_response.status_code == 200:
            print("✅ AI Security Service is healthy")
        else:
            print("❌ AI Security Service not responding properly")
            exit(1)
    except:
        print("❌ AI Security Service not reachable")
        exit(1)
    
    # Check if API server is running  
    try:
        api_health = requests.get("http://127.0.0.1:8001/health", timeout=5)
        if api_health.status_code == 200:
            print("✅ API Server is healthy")
        else:
            print("❌ API Server not responding properly")
            exit(1)
    except:
        print("❌ API Server not reachable")
        exit(1)
        
    print("\n" + "=" * 50)
    
    test_legitimate_request()
    test_malicious_request()
    
    print("\n🏁 Integration test completed!")