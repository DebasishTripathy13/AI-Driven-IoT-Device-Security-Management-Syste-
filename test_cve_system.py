"""
Test script to verify CVE management system functionality
"""
import asyncio
import sys
import json

async def test_cve_system():
    """Test the CVE management system"""
    print("🧪 Testing CVE Management System...")
    
    try:
        from cve_management_system import get_cve_manager
        
        # Initialize CVE manager
        print("📝 Initializing CVE manager...")
        cve_manager = await get_cve_manager()
        
        # Get dashboard data
        print("📊 Getting dashboard data...")
        dashboard_data = await cve_manager.get_cve_dashboard_data()
        
        # Display results
        print(f"\n✅ CVE System Test Results:")
        print(f"   📋 Total CVEs: {dashboard_data['summary']['total_cves']}")
        print(f"   🚨 Critical CVEs: {dashboard_data['summary']['critical_cves']}")
        print(f"   ⚠️  High Severity: {dashboard_data['summary']['high_severity_cves']}")
        print(f"   🔓 Exploitable: {dashboard_data['summary']['exploitable_cves']}")
        print(f"   🏥 Affected Devices: {dashboard_data['summary']['affected_devices']}")
        print(f"   🤖 ML Recommendations: {len(dashboard_data['recommendations'])}")
        
        # Show sample CVE data
        if dashboard_data['cves']:
            print(f"\n🔍 Sample CVE:")
            sample_cve = dashboard_data['cves'][0]
            print(f"   ID: {sample_cve['cve_id']}")
            print(f"   Severity: {sample_cve['severity_level']} ({sample_cve['severity_score']})")
            print(f"   Description: {sample_cve['description'][:100]}...")
            
            affected_devices = json.loads(sample_cve.get('affected_devices', '[]'))
            print(f"   Affected Devices: {', '.join(affected_devices) if affected_devices else 'None'}")
        
        # Show sample recommendation
        if dashboard_data['recommendations']:
            print(f"\n🤖 Sample ML Recommendation:")
            sample_rec = dashboard_data['recommendations'][0]
            print(f"   CVE: {sample_rec['cve_id']}")
            print(f"   Device: {sample_rec['device_id']}")
            print(f"   Urgency: {sample_rec['urgency_score']:.1f}%")
            print(f"   Recommended Time: {sample_rec['recommended_update_time']}")
            print(f"   Predicted Downtime: {sample_rec['predicted_downtime']} minutes")
        
        print(f"\n🎉 CVE Management System is working correctly!")
        return True
        
    except Exception as e:
        print(f"\n❌ CVE System Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test_cve_system())
    sys.exit(0 if result else 1)