# Debug test to check AI middleware error
import requests
import json

def test_middleware_debug():
    """Send a simple request to see the exact middleware error"""
    print("🔍 Debug test - simple request to trigger middleware...")
    
    # Very simple payload
    payload = {
        "deviceId": "med-ecg-001",
        "code": "print('test')",
        "language": "python"
    }
    
    try:
        # Add special header to force AI analysis
        headers = {
            "Content-Type": "application/json",
            "X-Force-AI-Analysis": "true",
            "User-Agent": "Debug-Test"
        }
        
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Text: {response.text}")
        
        # Try to parse JSON error
        if response.status_code == 500:
            try:
                error_data = response.json()
                print(f"Error Details: {json.dumps(error_data, indent=2)}")
            except:
                print("Could not parse error as JSON")
        
    except requests.exceptions.Timeout:
        print("Request timed out - likely hanging in middleware")
    except Exception as e:
        print(f"Request error: {e}")

def test_without_ai_header():
    """Test without forcing AI analysis to see if it's middleware specific"""
    print("\n🔍 Testing without AI analysis header...")
    
    payload = {
        "deviceId": "med-ecg-001", 
        "code": "print('no ai test')",
        "language": "python"
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8001/api/devices/med-ecg-001/code",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"No AI Header - Status: {response.status_code}")
        if response.status_code == 200:
            print("✅ Works without AI analysis")
        else:
            print(f"Response: {response.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_middleware_debug()
    test_without_ai_header()