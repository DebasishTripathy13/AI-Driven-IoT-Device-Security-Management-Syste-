# Direct API Test - Bypass AI Middleware temporarily
# This will help us isolate if the issue is in the AI middleware or the API endpoint

import requests
import json

def test_endpoint_directly():
    """Test the code execution endpoint with AI middleware disabled"""
    print("🔧 Testing code execution endpoint directly...")
    
    # Simple payload
    payload = {
        "deviceId": "med-ecg-001",
        "code": "print('Hello from device!')",
        "language": "python",
        "parameters": {}
    }
    
    try:
        # Add a special header to potentially bypass AI if needed
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Direct-Test"
        }
        
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✅ Endpoint is working - issue is likely in AI middleware")
        elif response.status_code == 500:
            print("❌ Endpoint has internal error - issue is in the API handler or dependencies")
        else:
            print(f"🤔 Unexpected status code: {response.status_code}")
            
    except Exception as e:
        print(f"Error: {e}")

def test_other_endpoints():
    """Test other endpoints to see if AI middleware is the issue"""
    print("\n🧪 Testing other protected endpoints...")
    
    # Test telemetry endpoint
    telemetry_payload = {
        "deviceIds": ["med-ecg-001"],
        "messageCount": 1
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8001/api/telemetry/send",
            json=telemetry_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Telemetry endpoint - Status: {response.status_code}")
        if response.status_code == 500:
            print("❌ Telemetry also failing - likely AI middleware issue")
        else:
            print("✅ Telemetry working - issue specific to code endpoint")
            
    except Exception as e:
        print(f"Telemetry test error: {e}")

if __name__ == "__main__":
    test_endpoint_directly()
    test_other_endpoints()