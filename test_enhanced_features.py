#!/usr/bin/env python3
"""
Enhanced Medical IoT Web App - Feature Test Script
Tests the new Code and Patch functionality
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_enhanced_features():
    print("🚀 Enhanced Medical IoT Web App - Feature Test")
    print("=" * 60)
    
    try:
        # Test system status
        print("\n📊 Testing enhanced system status...")
        response = requests.get(f"{BASE_URL}/api/status")
        if response.status_code == 200:
            status = response.json()
            print(f"✅ System Status: {status['message']}")
            print(f"   Connected: {status['data']['connected_devices']}")
            print(f"   Total: {status['data']['total_devices']}")
        
        # Get first device for testing
        response = requests.get(f"{BASE_URL}/api/devices")
        if response.status_code == 200:
            devices = response.json()
            if devices:
                test_device = devices[0]['deviceId']
                print(f"\n🎯 Using test device: {test_device}")
                
                # Test Code Execution
                print("\n💻 Testing Code Execution...")
                code_payload = {
                    "deviceId": test_device,
                    "messageType": "code",
                    "payload": {
                        "code": "print('Hello from IoT device!')\nprint('System status: OK')",
                        "language": "python",
                        "parameters": {}
                    },
                    "priority": "normal",
                    "timeout": 30
                }
                
                response = requests.post(f"{BASE_URL}/api/messages/send", 
                                       json=code_payload)
                if response.status_code == 200:
                    result = response.json()
                    print(f"✅ Code execution: {result['message']}")
                else:
                    print(f"❌ Code execution failed: {response.status_code}")
                
                # Test Patch Application
                print("\n🩹 Testing Patch Application...")
                patch_payload = {
                    "deviceId": test_device,
                    "messageType": "patch",
                    "payload": {
                        "patchData": {
                            "version": "1.0.1-test",
                            "changes": ["test_patch_001"],
                            "description": "Test patch from API"
                        },
                        "patchType": "configuration",
                        "rollbackEnabled": True
                    },
                    "priority": "high"
                }
                
                response = requests.post(f"{BASE_URL}/api/messages/send", 
                                       json=patch_payload)
                if response.status_code == 200:
                    result = response.json()
                    print(f"✅ Patch application: {result['message']}")
                else:
                    print(f"❌ Patch application failed: {response.status_code}")
                
                # Test Status Check
                print("\n🔍 Testing Status Check...")
                status_payload = {
                    "deviceId": test_device,
                    "statusType": "all"
                }
                
                response = requests.post(f"{BASE_URL}/api/devices/{test_device}/status", 
                                       json=status_payload)
                if response.status_code == 200:
                    result = response.json()
                    print(f"✅ Status check: {result['message']}")
                    print(f"   Health data retrieved successfully")
                else:
                    print(f"❌ Status check failed: {response.status_code}")
                
                # Test Custom Message with all types
                print("\n📨 Testing All Message Types...")
                message_types = ["normal", "status", "update"]
                for msg_type in message_types:
                    payload = {
                        "deviceId": test_device,
                        "messageType": msg_type,
                        "payload": {},
                        "priority": "normal"
                    }
                    
                    if msg_type == "update":
                        payload["payload"] = {
                            "properties": {"test": "value"},
                            "configuration": {"setting": "updated"}
                        }
                    
                    response = requests.post(f"{BASE_URL}/api/messages/send", json=payload)
                    if response.status_code == 200:
                        print(f"✅ {msg_type} message sent successfully")
                    else:
                        print(f"❌ {msg_type} message failed")
        
        print(f"\n🎉 Enhanced Feature Test Complete!")
        print(f"🌐 Web Interface: {BASE_URL}")
        print(f"📚 API Documentation: {BASE_URL}/docs")
        print(f"📋 New Features Available:")
        print(f"   • Send Code button on each device card")
        print(f"   • Send Patch button on each device card") 
        print(f"   • Quick Actions panel for bulk operations")
        print(f"   • Code templates (Python, JavaScript, Shell)")
        print(f"   • Patch templates (Config, Security, Performance)")
        print(f"   • Enhanced device details with quick actions")
        print(f"   • Real-time activity logging with user IP tracking")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to web server.")
        print("   Make sure the server is running: python main.py")
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_enhanced_features()