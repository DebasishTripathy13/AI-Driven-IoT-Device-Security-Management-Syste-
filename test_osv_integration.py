"""
Test OSV CVE Integration End-to-End
"""

import asyncio
import aiohttp
import json

async def test_osv_cve_system():
    """Test the complete OSV CVE system"""
    print("🧪 Testing OSV CVE Integration System...")
    
    # Test 1: Check if web server serves CVE page
    print("\n1️⃣ Testing web server CVE page...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:8000/cve-notification-board") as response:
                if response.status == 200:
                    content = await response.text()
                    if "CVE Notification Board" in content:
                        print("✅ CVE notification board page loads successfully")
                    else:
                        print("❌ CVE page content issue")
                else:
                    print(f"❌ CVE page failed: {response.status}")
    except Exception as e:
        print(f"❌ Web server test failed: {e}")
    
    # Test 2: Check CVE dashboard API
    print("\n2️⃣ Testing CVE dashboard API...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:8001/api/cve/dashboard") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ CVE dashboard API working - {data.get('summary', {}).get('total_cves', 0)} CVEs")
                else:
                    print(f"❌ CVE dashboard API failed: {response.status}")
    except Exception as e:
        print(f"❌ CVE dashboard API test failed: {e}")
    
    # Test 3: Test OSV refresh endpoint
    print("\n3️⃣ Testing OSV refresh functionality...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("http://127.0.0.1:8001/api/cve/refresh") as response:
                if response.status == 200:
                    data = await response.json()
                    total_cves = data.get('data', {}).get('total_cves', 0)
                    critical_cves = data.get('data', {}).get('critical_cves', 0)
                    print(f"✅ OSV refresh successful - {total_cves} CVEs ({critical_cves} critical)")
                    print(f"   Source: {data.get('data', {}).get('source', 'Unknown')}")
                else:
                    print(f"❌ OSV refresh failed: {response.status}")
    except Exception as e:
        print(f"❌ OSV refresh test failed: {e}")
    
    print("\n🎉 OSV CVE Integration test completed!")
    print("\n📋 Access Points:")
    print("   • CVE Dashboard: http://127.0.0.1:8000/cve-notification-board")
    print("   • Main Dashboard: http://127.0.0.1:8000")
    print("   • API Dashboard: http://127.0.0.1:8001/api/cve/dashboard")

if __name__ == "__main__":
    asyncio.run(test_osv_cve_system())