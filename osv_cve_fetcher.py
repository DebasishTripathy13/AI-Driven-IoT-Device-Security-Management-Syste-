"""
OSV (Open Source Vulnerabilities) CVE Fetcher
Uses Google's OSV database for real vulnerability data
No API key required - public access
"""

import aiohttp
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class OSVVulnerability:
    """OSV vulnerability data structure"""
    id: str
    summary: str
    details: str
    severity: Optional[str]
    published: str
    modified: str
    affected_packages: List[str]
    references: List[str]
    aliases: List[str]  # CVE IDs, etc.

class OSVFetcher:
    """Fetches vulnerability data from OSV API"""
    
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1"
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Medical-IoT-CVE-Manager/1.0'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def query_by_commit(self, commit_hash: str) -> List[OSVVulnerability]:
        """Query vulnerabilities by Git commit hash"""
        try:
            payload = {"commit": commit_hash}
            async with self.session.post(f"{self.base_url}/query", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_osv_response(data)
                else:
                    logger.error(f"OSV API error: {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Error querying OSV by commit: {e}")
            return []
    
    async def query_by_package(self, package_name: str, ecosystem: str = "PyPI") -> List[OSVVulnerability]:
        """Query vulnerabilities by package name"""
        try:
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            async with self.session.post(f"{self.base_url}/query", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_osv_response(data)
                else:
                    logger.error(f"OSV API error: {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Error querying OSV by package: {e}")
            return []
    
    async def get_vulnerability_details(self, vuln_id: str) -> Optional[OSVVulnerability]:
        """Get detailed information about a specific vulnerability"""
        try:
            async with self.session.get(f"{self.base_url}/vulns/{vuln_id}") as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_single_vulnerability(data)
                else:
                    logger.error(f"OSV API error for {vuln_id}: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error getting vulnerability details: {e}")
            return None
    
    async def query_medical_iot_vulnerabilities(self) -> List[OSVVulnerability]:
        """Query vulnerabilities related to medical IoT and healthcare packages"""
        medical_packages = [
            # Python packages commonly used in medical/IoT applications
            ("fastapi", "PyPI"),
            ("uvicorn", "PyPI"),
            ("httpx", "PyPI"),
            ("sqlalchemy", "PyPI"),
            ("cryptography", "PyPI"),
            ("requests", "PyPI"),
            ("flask", "PyPI"),
            ("django", "PyPI"),
            ("numpy", "PyPI"),
            ("pandas", "PyPI"),
            ("pillow", "PyPI"),
            ("opencv-python", "PyPI"),
            # Common IoT/embedded libraries
            ("paho-mqtt", "PyPI"),
            ("pyserial", "PyPI"),
            ("bleak", "PyPI"),  # Bluetooth LE
            ("azure-iot-device", "PyPI"),
            ("boto3", "PyPI"),  # AWS IoT
            # Node.js packages for IoT
            ("express", "npm"),
            ("mqtt", "npm"),
            ("serialport", "npm"),
            ("noble", "npm"),  # Bluetooth LE
            ("aws-iot-device-sdk", "npm"),
        ]
        
        all_vulnerabilities = []
        
        for package_name, ecosystem in medical_packages:
            try:
                vulns = await self.query_by_package(package_name, ecosystem)
                # Filter for recent vulnerabilities (last 2 years)
                recent_vulns = [
                    v for v in vulns 
                    if self._is_recent_vulnerability(v.published)
                ]
                all_vulnerabilities.extend(recent_vulns)
                
                # Add small delay to avoid rate limiting
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error querying {package_name}: {e}")
                continue
        
        # Remove duplicates based on ID
        unique_vulns = {v.id: v for v in all_vulnerabilities}
        return list(unique_vulns.values())
    
    def _parse_osv_response(self, data: Dict) -> List[OSVVulnerability]:
        """Parse OSV API response into vulnerability objects"""
        vulnerabilities = []
        
        vulns_data = data.get('vulns', [])
        if not isinstance(vulns_data, list):
            vulns_data = [vulns_data] if vulns_data else []
        
        for vuln_data in vulns_data:
            try:
                vuln = self._parse_single_vulnerability(vuln_data)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"Error parsing vulnerability: {e}")
                continue
        
        return vulnerabilities
    
    def _parse_single_vulnerability(self, data: Dict) -> Optional[OSVVulnerability]:
        """Parse a single vulnerability from OSV data"""
        try:
            # Extract severity information
            severity = None
            severity_data = data.get('database_specific', {}).get('severity')
            if severity_data:
                if isinstance(severity_data, list) and severity_data:
                    severity = severity_data[0].get('score', 'UNKNOWN')
                elif isinstance(severity_data, dict):
                    severity = severity_data.get('score', 'UNKNOWN')
            
            # Extract affected packages
            affected_packages = []
            for affected in data.get('affected', []):
                package = affected.get('package', {})
                if package.get('name'):
                    affected_packages.append(f"{package.get('ecosystem', 'Unknown')}: {package['name']}")
            
            # Extract references
            references = [ref.get('url', '') for ref in data.get('references', []) if ref.get('url')]
            
            # Extract aliases (CVE IDs, etc.)
            aliases = data.get('aliases', [])
            
            return OSVVulnerability(
                id=data.get('id', ''),
                summary=data.get('summary', ''),
                details=data.get('details', ''),
                severity=severity,
                published=data.get('published', ''),
                modified=data.get('modified', ''),
                affected_packages=affected_packages,
                references=references,
                aliases=aliases
            )
        except Exception as e:
            logger.error(f"Error parsing single vulnerability: {e}")
            return None
    
    def _is_recent_vulnerability(self, published_date: str) -> bool:
        """Check if vulnerability was published in the last 2 years"""
        try:
            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            two_years_ago = datetime.now() - timedelta(days=730)
            return pub_date.replace(tzinfo=None) > two_years_ago
        except:
            return True  # Include if we can't parse the date

async def test_osv_fetcher():
    """Test the OSV fetcher with medical IoT queries"""
    print("🔍 Testing OSV Vulnerability Fetcher...")
    
    async with OSVFetcher() as fetcher:
        # Test 1: Query by commit hash (example from your request)
        print("\n📋 Testing commit hash query...")
        commit_vulns = await fetcher.query_by_commit("6879efc2c1596d11a6a6ad296f80063b558d5e0f")
        print(f"Found {len(commit_vulns)} vulnerabilities for commit")
        
        # Test 2: Query specific medical/IoT packages
        print("\n🏥 Testing medical IoT package vulnerabilities...")
        iot_vulns = await fetcher.query_medical_iot_vulnerabilities()
        print(f"Found {len(iot_vulns)} medical/IoT related vulnerabilities")
        
        # Show sample vulnerabilities
        print("\n📊 Sample vulnerabilities:")
        for i, vuln in enumerate(iot_vulns[:3]):  # Show first 3
            cve_ids = [alias for alias in vuln.aliases if alias.startswith('CVE-')]
            print(f"  {i+1}. {vuln.id}")
            print(f"     Summary: {vuln.summary[:100]}...")
            print(f"     Severity: {vuln.severity or 'Unknown'}")
            print(f"     CVE IDs: {', '.join(cve_ids) if cve_ids else 'None'}")
            print(f"     Affected: {', '.join(vuln.affected_packages[:2])}")
            print()
    
    print("✅ OSV Fetcher test completed!")

if __name__ == "__main__":
    asyncio.run(test_osv_fetcher())