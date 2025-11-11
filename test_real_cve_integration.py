#!/usr/bin/env python3
"""
Test Real CVE Integration with NIST NVD
"""

import asyncio
import sys
from cve_management_system import get_cve_manager

async def test_real_cve_integration():
    """Test fetching real CVE data from NIST NVD"""
    print("🔍 Testing Real CVE Integration with NIST NVD...")
    print("=" * 60)
    
    try:
        # Get CVE manager
        manager = await get_cve_manager()
        
        # Test fetching real CVEs from NVD
        print("📡 Fetching real CVE data from NIST NVD...")
        real_cves = await manager.fetch_real_cves_from_nvd()
        
        if real_cves:
            print(f"✅ Successfully fetched {len(real_cves)} real CVEs from NVD")
            print("\n🏥 Sample Real CVE:")
            sample_cve = real_cves[0]
            print(f"   ID: {sample_cve.cve_id}")
            print(f"   Severity: {sample_cve.severity_level} ({sample_cve.severity_score})")
            print(f"   Published: {sample_cve.published_date}")
            print(f"   Description: {sample_cve.description[:100]}...")
            print(f"   Affected Systems: {sample_cve.affected_systems[:2]}")
            print(f"   Attack Vector: {sample_cve.attack_vector}")
            print(f"   Patch Available: {sample_cve.patch_available}")
            print(f"   Exploit Available: {sample_cve.exploit_available}")
            
            # Store in database
            for cve in real_cves:
                manager.db.store_cve(cve)
            print(f"💾 Stored {len(real_cves)} real CVEs in database")
            
        else:
            print("⚠️  No real CVEs fetched (may be due to API rate limits or network issues)")
        
        # Test medical device specific CVEs
        print("\n🏥 Fetching medical device specific CVEs...")
        medical_cves = await manager.fetch_medical_device_cves()
        
        if medical_cves:
            print(f"✅ Successfully fetched {len(medical_cves)} medical device CVEs")
            print("\n🩺 Sample Medical Device CVE:")
            sample_medical = medical_cves[0]
            print(f"   ID: {sample_medical.cve_id}")
            print(f"   Severity: {sample_medical.severity_level} ({sample_medical.severity_score})")
            print(f"   Description: {sample_medical.description[:100]}...")
            print(f"   Affected Devices: {sample_medical.affected_devices}")
        else:
            print("⚠️  No medical device CVEs fetched")
        
        # Test full update process
        print("\n🔄 Testing full CVE data update process...")
        new_cves_count = await manager.update_cve_data_from_sources()
        print(f"✅ Update process completed. Added {new_cves_count} new CVEs")
        
        # Get final dashboard data
        print("\n📊 Getting final dashboard data...")
        dashboard_data = await manager.get_cve_dashboard_data()
        
        print(f"\n🎯 Final Results:")
        print(f"   📋 Total CVEs: {dashboard_data['summary']['total_cves']}")
        print(f"   🚨 Critical CVEs: {dashboard_data['summary']['critical_cves']}")
        print(f"   ⚠️  High Severity: {dashboard_data['summary']['high_severity_cves']}")
        print(f"   🔓 Exploitable: {dashboard_data['summary']['exploitable_cves']}")
        print(f"   🏥 Affected Devices: {dashboard_data['summary']['affected_devices']}")
        print(f"   🤖 ML Recommendations: {len(dashboard_data['recommendations'])}")
        
        print("\n✅ Real CVE Integration Test Complete!")
        print("🌐 You can now access real CVE data at: http://127.0.0.1:8000/cve-notification-board")
        print("🔄 Use the 'Refresh from NVD' button to get the latest CVE data")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing real CVE integration: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_real_cve_integration())
    sys.exit(0 if success else 1)