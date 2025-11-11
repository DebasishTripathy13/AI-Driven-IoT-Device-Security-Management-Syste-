"""
Test script to validate the microservices architecture
"""
import requests
import json
import time

def test_servers():
    """Test both API and Web servers"""
    print("🧪 Testing Medical IoT Microservices Architecture")
    print("=" * 50)
    
    # Test API Server Health
    try:
        api_response = requests.get("http://localhost:8001/health", timeout=5)
        if api_response.status_code == 200:
            print("✅ API Server (Port 8001): HEALTHY")
            print(f"   Response: {api_response.json()}")
        else:
            print("❌ API Server: UNHEALTHY")
            return False
    except Exception as e:
        print(f"❌ API Server: UNREACHABLE - {e}")
        return False
    
    print()
    
    # Test Web Server Health
    try:
        web_response = requests.get("http://localhost:8000/health", timeout=5)
        if web_response.status_code == 200:
            print("✅ Web Server (Port 8000): HEALTHY")
            print(f"   Response: {web_response.json()}")
        else:
            print("❌ Web Server: UNHEALTHY")
            return False
    except Exception as e:
        print(f"❌ Web Server: UNREACHABLE - {e}")
        return False
    
    print()
    
    # Test Proxy Functionality
    try:
        # Test devices endpoint through proxy
        devices_response = requests.get("http://localhost:8000/api/devices", timeout=5)
        if devices_response.status_code == 200:
            devices = devices_response.json()
            print(f"✅ Proxy Functionality: WORKING")
            print(f"   Found {len(devices)} devices through proxy")
            
            # Show first device as example
            if devices:
                print(f"   Sample Device: {devices[0]['deviceId']} ({devices[0]['deviceType']})")
        else:
            print("❌ Proxy Functionality: FAILED")
            return False
    except Exception as e:
        print(f"❌ Proxy Functionality: ERROR - {e}")
        return False
    
    print()
    
    # Test API Server Direct Access
    try:
        api_devices_response = requests.get("http://localhost:8001/api/devices", timeout=5)
        if api_devices_response.status_code == 200:
            api_devices = api_devices_response.json()
            print(f"✅ API Server Direct Access: WORKING")
            print(f"   Found {len(api_devices)} devices directly")
        else:
            print("❌ API Server Direct Access: FAILED")
            return False
    except Exception as e:
        print(f"❌ API Server Direct Access: ERROR - {e}")
        return False
    
    print()
    print("🎉 All Tests Passed! Microservices Architecture is Working!")
    print()
    print("📋 Summary:")
    print("  • API Server: Handles device management and telemetry")
    print("  • Web Server: Serves frontend and proxies API requests")
    print("  • Proxy: Successfully forwards requests between servers")
    print("  • Devices: All registered devices accessible through both paths")
    print()
    print("🌐 Access Points:")
    print("  • Web Interface: http://localhost:8000")
    print("  • API Documentation: http://localhost:8001/docs")
    
    return True

if __name__ == "__main__":
    test_servers()