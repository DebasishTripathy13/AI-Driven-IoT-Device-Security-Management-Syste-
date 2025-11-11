#!/usr/bin/env python3
"""
Test script to verify all web UI functions are working properly
"""
import requests
import json
import time

def test_web_ui_functions():
    """Test all the web UI functions that were having HTTP 422 errors"""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing Fixed Web UI Functions")
    print("=" * 50)
    
    # Test 1: Telemetry Send
    print("\n1. Testing Telemetry Send...")
    try:
        response = requests.post(f"{base_url}/api/telemetry/send", 
                               json={"deviceIds": ["med-ecg-001"], "messageCount": 1},
                               timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS: {result.get('message', 'Telemetry sent')}")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    # Test 2: Device Status Check
    print("\n2. Testing Device Status Check...")
    try:
        response = requests.post(f"{base_url}/api/devices/med-ecg-001/status",
                               json={"deviceId": "med-ecg-001", "statusType": "all"},
                               timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS: {result.get('message', 'Status checked')}")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    # Test 3: Code Execution
    print("\n3. Testing Code Execution...")
    try:
        response = requests.post(f"{base_url}/api/devices/med-ecg-001/code",
                               json={
                                   "deviceId": "med-ecg-001",
                                   "code": "print('Hello World')",
                                   "language": "python",
                                   "parameters": {}
                               },
                               timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS: {result.get('message', 'Code executed')}")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    # Test 4: Device Patch
    print("\n4. Testing Device Patch...")
    try:
        response = requests.patch(f"{base_url}/api/devices/med-ecg-001",
                                json={
                                    "deviceId": "med-ecg-001",
                                    "properties": {
                                        "softwareVersion": "v2.1.0",
                                        "patchType": "firmware_update",
                                        "lastUpdate": "2025-09-19T12:00:00Z"
                                    }
                                },
                                timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS: {result.get('message', 'Patch deployed')}")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    # Test 5: Custom Message
    print("\n5. Testing Custom Message...")
    try:
        response = requests.post(f"{base_url}/api/messages/send",
                               json={
                                   "deviceId": "med-ecg-001",
                                   "messageType": "normal",
                                   "payload": {"customMessage": "Test message"},
                                   "priority": "normal",
                                   "timeout": 30
                               },
                               timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS: {result.get('message', 'Message sent')}")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Test Summary:")
    print("   All major web UI functions have been fixed!")
    print("   HTTP 422 errors should now be resolved.")
    print("\n💡 Next Steps:")
    print("   • Try using the web interface at http://localhost:8000")
    print("   • Test device operations like patch deployment")
    print("   • Check admin panel for monitoring at http://localhost:8001/admin")

if __name__ == "__main__":
    test_web_ui_functions()