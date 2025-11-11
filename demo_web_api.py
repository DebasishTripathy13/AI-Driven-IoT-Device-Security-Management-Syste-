#!/usr/bin/env python3
"""
Quick demo script to show the web application capabilities
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def demo_api():
    print("🌐 Medical IoT Web API Demo")
    print("=" * 50)
    
    try:
        # Test system status
        print("\n📊 Getting system status...")
        response = requests.get(f"{BASE_URL}/api/status")
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Status: {status['message']}")
            print(f"   Connected: {status['data']['connected_devices']}")
            print(f"   Total: {status['data']['total_devices']}")
        else:
            print(f"❌ Status check failed: {response.status_code}")
            return

        # Get all devices
        print("\n🏥 Fetching devices...")
        response = requests.get(f"{BASE_URL}/api/devices")
        if response.status_code == 200:
            devices = response.json()
            print(f"✅ Found {len(devices)} devices:")
            for device in devices[:3]:  # Show first 3
                print(f"   - {device['deviceId']}: {device['deviceType']} ({device['status']})")
        else:
            print(f"❌ Device fetch failed: {response.status_code}")
            return

        # Get sample telemetry
        print("\n📡 Getting sample telemetry...")
        device_types = ["ECG", "PulseOximeter", "BloodPressureMonitor"]
        for device_type in device_types:
            response = requests.get(f"{BASE_URL}/api/telemetry/sample/{device_type}")
            if response.status_code == 200:
                sample = response.json()
                print(f"✅ {device_type}: {sample['data']['timestamp']}")
            else:
                print(f"❌ Sample failed for {device_type}")

        print(f"\n🎉 API Demo Complete!")
        print(f"🌐 Open your browser to: {BASE_URL}")
        print(f"📚 API Documentation: {BASE_URL}/docs")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to web server.")
        print("   Make sure the server is running: python main.py")
    except Exception as e:
        print(f"❌ Demo failed: {e}")

if __name__ == "__main__":
    demo_api()