"""
Test script for NVD CVE integration
Shows how to set up and use real CVE data from NIST National Vulnerability Database
"""

import asyncio
import os
import sys
from cve_management_system import get_cve_manager

async def test_nvd_integration():
    """Test the NVD CVE integration"""
    print("🔐 NVD API Key Setup Instructions:")
    print("=" * 50)
    print("1. Visit: https://nvd.nist.gov/developers/request-an-api-key")
    print("2. Register for a free API key (takes ~5 minutes)")
    print("3. Set your API key using one of these methods:")
    print("   Method A - Environment Variable:")
    print("     Windows: set NVD_API_KEY=your_api_key_here")
    print("     Linux/Mac: export NVD_API_KEY=your_api_key_here")
    print("   Method B - Create .env file with:")
    print("     NVD_API_KEY=your_api_key_here")
    print()
    
    # Check if API key is available
    api_key = os.getenv('NVD_API_KEY')
    if api_key:
        print(f"✅ API Key found: {api_key[:8]}...{api_key[-4:]}")
        print("🚀 Using unlimited NVD API access")
    else:
        print("⚠️  No API key found - using rate-limited public access")
        print("📊 Limit: 50 requests per 30 seconds")
    
    print("\n🔍 Testing CVE Management System...")
    print("=" * 50)
    
    try:
        # Initialize CVE manager
        cve_manager = await get_cve_manager()
        
        # Get dashboard data
        dashboard_data = await cve_manager.get_cve_dashboard_data()
        
        print(f"📋 Total CVEs: {dashboard_data['summary']['total_cves']}")
        print(f"🚨 Critical CVEs: {dashboard_data['summary']['critical_cves']}")
        print(f"⚠️  High Severity: {dashboard_data['summary']['high_severity_cves']}")
        print(f"🔓 Exploitable: {dashboard_data['summary']['exploitable_cves']}")
        print(f"🏥 Affected Devices: {dashboard_data['summary']['affected_devices']}")
        
        # Show sample CVEs
        print("\n📝 Sample CVEs:")
        print("-" * 30)
        for i, cve in enumerate(dashboard_data['cves'][:3], 1):
            print(f"{i}. {cve['cve_id']} - {cve['severity_level']} ({cve['severity_score']})")
            print(f"   {cve['description'][:80]}...")
            print()
        
        print("✅ CVE Management System is working correctly!")
        
        # Instructions for web interface
        print("\n🌐 Access Web Interface:")
        print("=" * 30)
        print("1. Make sure servers are running:")
        print("   - Web Server: http://127.0.0.1:8000")
        print("   - API Server: http://127.0.0.1:8001")
        print("2. Visit: http://127.0.0.1:8000/cve-notification-board")
        print("3. Click 'Refresh CVE Data' to fetch latest from NVD")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n🔧 Troubleshooting:")
        print("- Ensure internet connection is available")
        print("- Check if API key is valid (if using)")
        print("- Verify all required packages are installed:")
        print("  pip install aiohttp scikit-learn pandas numpy")

if __name__ == "__main__":
    asyncio.run(test_nvd_integration())