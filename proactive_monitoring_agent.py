"""
Proactive Monitoring Agent for IoT Security
Fetches CVE data from online databases and matches against device firmware/software
Provides early warning system for vulnerable IoT devices
"""

import asyncio
import aiohttp
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """CVE Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

@dataclass
class CVEData:
    """CVE vulnerability data structure"""
    cve_id: str
    description: str
    severity: SeverityLevel
    score: float
    published_date: str
    modified_date: str
    affected_software: List[str]
    affected_versions: List[str]
    cwe_id: Optional[str] = None
    references: List[str] = None
    exploit_available: bool = False
    patch_available: bool = False
    vendor_advisory: Optional[str] = None

@dataclass
class DeviceVulnerability:
    """Device vulnerability assessment result"""
    device_id: str
    device_type: str
    firmware_version: str
    software_version: str
    cve_matches: List[CVEData]
    risk_score: float
    recommendations: List[str]
    last_assessed: str

class ProactiveMonitoringAgent:
    """
    Advanced CVE monitoring and vulnerability assessment agent
    """
    
    def __init__(self, db_path: str = "data/security_monitoring.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._lock = threading.Lock()
        
        # CVE data sources
        self.cve_sources = {
            "nist": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "mitre": "https://cve.mitre.org/data/downloads/allitems.xml",
            "cisa": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
        
        # IoT-specific vendor patterns
        self.iot_vendors = [
            "raspberry pi", "arduino", "esp32", "esp8266", "nvidia jetson",
            "intel nuc", "beaglebone", "orange pi", "rock pi", "banana pi",
            "siemens", "schneider electric", "honeywell", "ge", "abb",
            "philips", "samsung", "lg", "sony", "panasonic", "bosch",
            "nest", "ring", "arlo", "tp-link", "netgear", "linksys",
            "ubiquiti", "cisco", "juniper", "fortinet", "palo alto"
        ]
        
        # Common IoT software patterns
        self.iot_software_patterns = [
            r"linux.*embedded", r"rtos", r"freertos", r"zephyr", r"contiki",
            r"riot.*os", r"mbedos", r"nucleus", r"threadx", r"vxworks",
            r"busybox", r"dropbear", r"openssh", r"lighttpd", r"nginx",
            r"mosquitto", r"mqtt", r"coap", r"zigbee", r"z-wave",
            r"bluetooth.*le", r"wifi.*direct", r"lorawan", r"sigfox"
        ]
        
        self._init_database()
        
    def _init_database(self):
        """Initialize monitoring database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # CVE data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    published_date TEXT NOT NULL,
                    modified_date TEXT NOT NULL,
                    affected_software TEXT NOT NULL,
                    affected_versions TEXT NOT NULL,
                    cwe_id TEXT,
                    reference_links TEXT,
                    exploit_available BOOLEAN DEFAULT 0,
                    patch_available BOOLEAN DEFAULT 0,
                    vendor_advisory TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Device vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    firmware_version TEXT NOT NULL,
                    software_version TEXT NOT NULL,
                    cve_matches TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    recommendations TEXT NOT NULL,
                    last_assessed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending'
                )
            """)
            
            # Monitoring tasks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    completed_at DATETIME,
                    results TEXT,
                    error_message TEXT
                )
            """)
            
            conn.commit()
            logger.info("Proactive monitoring database initialized")
    
    async def fetch_cve_data(self, days_back: int = 7) -> List[CVEData]:
        """Fetch recent CVE data from multiple sources"""
        logger.info(f"Fetching CVE data for the last {days_back} days...")
        
        # Record monitoring task
        task_id = self._record_task_start("cve_fetch")
        
        try:
            all_cves = []
            
            # Fetch from NIST NVD
            nist_cves = await self._fetch_nist_cves(days_back)
            all_cves.extend(nist_cves)
            
            # Fetch from CISA Known Exploited Vulnerabilities
            cisa_cves = await self._fetch_cisa_cves()
            all_cves.extend(cisa_cves)
            
            # Filter for IoT-relevant CVEs
            iot_cves = self._filter_iot_relevant_cves(all_cves)
            
            # Store in database
            await self._store_cve_data(iot_cves)
            
            self._record_task_completion(task_id, f"Fetched {len(iot_cves)} IoT-relevant CVEs")
            logger.info(f"Successfully fetched {len(iot_cves)} IoT-relevant CVEs")
            
            return iot_cves
            
        except Exception as e:
            self._record_task_error(task_id, str(e))
            logger.error(f"Failed to fetch CVE data: {e}")
            return []
    
    async def _fetch_nist_cves(self, days_back: int) -> List[CVEData]:
        """Fetch CVEs from NIST NVD API"""
        cves = []
        
        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # Format dates for API
            start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            async with aiohttp.ClientSession() as session:
                url = f"{self.cve_sources['nist']}?pubStartDate={start_str}&pubEndDate={end_str}&resultsPerPage=2000"
                
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for item in data.get('vulnerabilities', []):
                            cve_item = item.get('cve', {})
                            
                            # Extract CVE data
                            cve = self._parse_nist_cve(cve_item)
                            if cve:
                                cves.append(cve)
                    
                    else:
                        logger.warning(f"NIST API returned status {response.status}")
                        
        except Exception as e:
            logger.error(f"Error fetching NIST CVEs: {e}")
        
        return cves
    
    async def _fetch_cisa_cves(self) -> List[CVEData]:
        """Fetch Known Exploited Vulnerabilities from CISA"""
        cves = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.cve_sources['cisa'], timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for vuln in data.get('vulnerabilities', []):
                            cve = CVEData(
                                cve_id=vuln.get('cveID', ''),
                                description=vuln.get('vulnerabilityName', ''),
                                severity=SeverityLevel.HIGH,  # CISA KEV are high priority
                                score=8.0,  # Default high score
                                published_date=vuln.get('dateAdded', ''),
                                modified_date=vuln.get('dateAdded', ''),
                                affected_software=[vuln.get('product', '')],
                                affected_versions=[vuln.get('vendorProject', '')],
                                exploit_available=True,  # CISA KEV indicates known exploits
                                references=[vuln.get('shortDescription', '')]
                            )
                            cves.append(cve)
                    
                    else:
                        logger.warning(f"CISA API returned status {response.status}")
                        
        except Exception as e:
            logger.error(f"Error fetching CISA CVEs: {e}")
        
        return cves
    
    def _parse_nist_cve(self, cve_item: Dict) -> Optional[CVEData]:
        """Parse NIST CVE JSON format"""
        try:
            cve_id = cve_item.get('id', '')
            descriptions = cve_item.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Get CVSS metrics
            metrics = cve_item.get('metrics', {})
            cvssv3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            
            score = 0.0
            severity = SeverityLevel.UNKNOWN
            
            if cvssv3:
                cvss_data = cvssv3[0].get('cvssData', {})
                score = cvss_data.get('baseScore', 0.0)
                severity_str = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                severity = SeverityLevel(severity_str) if severity_str in [s.value for s in SeverityLevel] else SeverityLevel.UNKNOWN
            
            # Get affected software
            configurations = cve_item.get('configurations', [])
            affected_software = []
            affected_versions = []
            
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_name = cpe_match.get('criteria', '')
                        if cpe_name:
                            # Parse CPE name to extract software and version
                            parts = cpe_name.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else '*'
                                
                                affected_software.append(f"{vendor}:{product}")
                                if version != '*':
                                    affected_versions.append(version)
            
            # Get references
            references = []
            for ref in cve_item.get('references', []):
                references.append(ref.get('url', ''))
            
            # Get CWE
            weaknesses = cve_item.get('weaknesses', [])
            cwe_id = None
            if weaknesses:
                cwe_descriptions = weaknesses[0].get('description', [])
                if cwe_descriptions:
                    cwe_id = cwe_descriptions[0].get('value', '')
            
            return CVEData(
                cve_id=cve_id,
                description=description,
                severity=severity,
                score=score,
                published_date=cve_item.get('published', ''),
                modified_date=cve_item.get('lastModified', ''),
                affected_software=affected_software,
                affected_versions=affected_versions,
                cwe_id=cwe_id,
                references=references
            )
            
        except Exception as e:
            logger.error(f"Error parsing NIST CVE: {e}")
            return None
    
    def _filter_iot_relevant_cves(self, cves: List[CVEData]) -> List[CVEData]:
        """Filter CVEs that are relevant to IoT devices"""
        iot_cves = []
        
        for cve in cves:
            is_iot_relevant = False
            
            # Check description for IoT keywords
            description_lower = cve.description.lower()
            
            # Check for IoT vendor mentions
            for vendor in self.iot_vendors:
                if vendor.lower() in description_lower:
                    is_iot_relevant = True
                    break
            
            # Check for IoT software patterns
            if not is_iot_relevant:
                for pattern in self.iot_software_patterns:
                    if re.search(pattern, description_lower):
                        is_iot_relevant = True
                        break
            
            # Check affected software
            if not is_iot_relevant:
                for software in cve.affected_software:
                    software_lower = software.lower()
                    for vendor in self.iot_vendors:
                        if vendor.lower() in software_lower:
                            is_iot_relevant = True
                            break
                    if is_iot_relevant:
                        break
            
            # IoT-specific keywords in description
            iot_keywords = ['iot', 'internet of things', 'embedded', 'firmware', 'router', 'gateway', 'sensor', 'actuator', 'controller']
            if not is_iot_relevant:
                for keyword in iot_keywords:
                    if keyword in description_lower:
                        is_iot_relevant = True
                        break
            
            if is_iot_relevant:
                iot_cves.append(cve)
        
        return iot_cves
    
    async def _store_cve_data(self, cves: List[CVEData]):
        """Store CVE data in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    for cve in cves:
                        cursor.execute("""
                            INSERT OR REPLACE INTO cve_data 
                            (cve_id, description, severity, score, published_date, modified_date,
                             affected_software, affected_versions, cwe_id, reference_links, 
                             exploit_available, patch_available, vendor_advisory)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            cve.cve_id, cve.description, cve.severity.value, cve.score,
                            cve.published_date, cve.modified_date,
                            json.dumps(cve.affected_software), json.dumps(cve.affected_versions),
                            cve.cwe_id, json.dumps(cve.references or []),
                            cve.exploit_available, cve.patch_available, cve.vendor_advisory
                        ))
                    
                    conn.commit()
                    logger.info(f"Stored {len(cves)} CVEs in database")
                    
            except Exception as e:
                logger.error(f"Failed to store CVE data: {e}")
    
    async def assess_device_vulnerabilities(self, devices: List[Dict]) -> List[DeviceVulnerability]:
        """Assess vulnerabilities for a list of IoT devices"""
        logger.info(f"Assessing vulnerabilities for {len(devices)} devices...")
        
        task_id = self._record_task_start("vulnerability_assessment")
        assessments = []
        
        try:
            # Get all stored CVEs
            stored_cves = await self._get_stored_cves()
            
            for device in devices:
                assessment = await self._assess_single_device(device, stored_cves)
                if assessment:
                    assessments.append(assessment)
            
            # Store assessments
            await self._store_vulnerability_assessments(assessments)
            
            self._record_task_completion(task_id, f"Assessed {len(assessments)} devices")
            logger.info(f"Completed vulnerability assessment for {len(assessments)} devices")
            
        except Exception as e:
            self._record_task_error(task_id, str(e))
            logger.error(f"Failed vulnerability assessment: {e}")
        
        return assessments
    
    async def _assess_single_device(self, device: Dict, cves: List[CVEData]) -> Optional[DeviceVulnerability]:
        """Assess vulnerabilities for a single device"""
        try:
            device_id = device.get('deviceId', '')
            device_type = device.get('deviceType', '')
            firmware_version = device.get('firmwareVersion', '')
            software_version = device.get('softwareVersion', '')
            
            matching_cves = []
            
            # Match CVEs against device
            for cve in cves:
                if self._is_device_affected(device, cve):
                    matching_cves.append(cve)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(matching_cves)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(device, matching_cves)
            
            return DeviceVulnerability(
                device_id=device_id,
                device_type=device_type,
                firmware_version=firmware_version,
                software_version=software_version,
                cve_matches=matching_cves,
                risk_score=risk_score,
                recommendations=recommendations,
                last_assessed=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error assessing device {device.get('deviceId', 'unknown')}: {e}")
            return None
    
    def _is_device_affected(self, device: Dict, cve: CVEData) -> bool:
        """Check if a device is affected by a CVE"""
        device_software = [
            device.get('manufacturer', '').lower(),
            device.get('deviceType', '').lower(),
            device.get('osName', '').lower(),
            device.get('softwareVersion', '').lower(),
            device.get('firmwareVersion', '').lower()
        ]
        
        # Check against affected software
        for affected in cve.affected_software:
            affected_parts = affected.lower().split(':')
            for part in affected_parts:
                for dev_software in device_software:
                    if part in dev_software or dev_software in part:
                        return True
        
        # Check version matching if applicable
        device_version = device.get('firmwareVersion', '') or device.get('softwareVersion', '')
        if device_version and cve.affected_versions:
            for affected_version in cve.affected_versions:
                if self._version_matches(device_version, affected_version):
                    return True
        
        return False
    
    def _version_matches(self, device_version: str, affected_version: str) -> bool:
        """Check if device version matches affected version pattern"""
        # Simple version matching - can be enhanced
        if affected_version == '*' or affected_version == device_version:
            return True
        
        # Handle version ranges (basic implementation)
        if '<' in affected_version or '>' in affected_version:
            # For now, assume match for range queries
            return True
        
        return False
    
    def _calculate_risk_score(self, cves: List[CVEData]) -> float:
        """Calculate overall risk score for device based on CVEs"""
        if not cves:
            return 0.0
        
        total_score = 0.0
        weight_multipliers = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.UNKNOWN: 0.2
        }
        
        for cve in cves:
            base_score = cve.score
            severity_multiplier = weight_multipliers.get(cve.severity, 0.5)
            exploit_multiplier = 1.5 if cve.exploit_available else 1.0
            
            cve_risk = base_score * severity_multiplier * exploit_multiplier
            total_score += cve_risk
        
        # Normalize to 0-10 scale
        return min(total_score / len(cves), 10.0)
    
    def _generate_recommendations(self, device: Dict, cves: List[CVEData]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        if not cves:
            recommendations.append("Device appears secure - no known vulnerabilities found")
            return recommendations
        
        critical_cves = [cve for cve in cves if cve.severity == SeverityLevel.CRITICAL]
        high_cves = [cve for cve in cves if cve.severity == SeverityLevel.HIGH]
        
        if critical_cves:
            recommendations.append(f"URGENT: {len(critical_cves)} critical vulnerabilities found - immediate patching required")
        
        if high_cves:
            recommendations.append(f"HIGH PRIORITY: {len(high_cves)} high-severity vulnerabilities - schedule patching within 24-48 hours")
        
        exploitable_cves = [cve for cve in cves if cve.exploit_available]
        if exploitable_cves:
            recommendations.append(f"WARNING: {len(exploitable_cves)} vulnerabilities have known exploits - isolate device if possible")
        
        # Specific recommendations
        recommendations.append("Update device firmware to latest version")
        recommendations.append("Review device network access and restrict unnecessary connections")
        recommendations.append("Enable device security logging if available")
        recommendations.append("Consider device replacement if patches are unavailable")
        
        return recommendations
    
    async def _get_stored_cves(self) -> List[CVEData]:
        """Retrieve stored CVEs from database"""
        cves = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT cve_id, description, severity, score, published_date, modified_date,
                           affected_software, affected_versions, cwe_id, reference_links,
                           exploit_available, patch_available, vendor_advisory
                    FROM cve_data
                    ORDER BY score DESC, published_date DESC
                """)
                
                for row in cursor.fetchall():
                    cve = CVEData(
                        cve_id=row[0],
                        description=row[1],
                        severity=SeverityLevel(row[2]),
                        score=row[3],
                        published_date=row[4],
                        modified_date=row[5],
                        affected_software=json.loads(row[6]) if row[6] else [],
                        affected_versions=json.loads(row[7]) if row[7] else [],
                        cwe_id=row[8],
                        references=json.loads(row[9]) if row[9] else [],
                        exploit_available=bool(row[10]),
                        patch_available=bool(row[11]),
                        vendor_advisory=row[12]
                    )
                    cves.append(cve)
                    
        except Exception as e:
            logger.error(f"Failed to retrieve stored CVEs: {e}")
        
        return cves
    
    async def _store_vulnerability_assessments(self, assessments: List[DeviceVulnerability]):
        """Store vulnerability assessments in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    for assessment in assessments:
                        cursor.execute("""
                            INSERT OR REPLACE INTO device_vulnerabilities
                            (device_id, device_type, firmware_version, software_version,
                             cve_matches, risk_score, recommendations, last_assessed)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            assessment.device_id, assessment.device_type,
                            assessment.firmware_version, assessment.software_version,
                            json.dumps([asdict(cve) for cve in assessment.cve_matches]),
                            assessment.risk_score, json.dumps(assessment.recommendations),
                            assessment.last_assessed
                        ))
                    
                    conn.commit()
                    logger.info(f"Stored {len(assessments)} vulnerability assessments")
                    
            except Exception as e:
                logger.error(f"Failed to store vulnerability assessments: {e}")
    
    def _record_task_start(self, task_type: str) -> int:
        """Record the start of a monitoring task"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO monitoring_tasks (task_type, status)
                VALUES (?, 'running')
            """, (task_type,))
            conn.commit()
            return cursor.lastrowid
    
    def _record_task_completion(self, task_id: int, results: str):
        """Record successful task completion"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE monitoring_tasks 
                SET status = 'completed', completed_at = CURRENT_TIMESTAMP, results = ?
                WHERE id = ?
            """, (results, task_id))
            conn.commit()
    
    def _record_task_error(self, task_id: int, error_message: str):
        """Record task error"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE monitoring_tasks 
                SET status = 'error', completed_at = CURRENT_TIMESTAMP, error_message = ?
                WHERE id = ?
            """, (error_message, task_id))
            conn.commit()
    
    async def run_continuous_monitoring(self, interval_hours: int = 6):
        """Run continuous CVE monitoring"""
        logger.info(f"Starting continuous monitoring with {interval_hours} hour intervals")
        
        while True:
            try:
                # Fetch latest CVEs
                await self.fetch_cve_data(days_back=1)
                
                # Wait for next interval
                await asyncio.sleep(interval_hours * 3600)
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

# Global monitoring agent instance
monitoring_agent = ProactiveMonitoringAgent()

async def main():
    """Test the Proactive Monitoring Agent"""
    print("Testing Proactive Monitoring Agent...")
    
    # Fetch recent CVE data
    cves = await monitoring_agent.fetch_cve_data(days_back=7)
    print(f"Fetched {len(cves)} IoT-relevant CVEs")
    
    # Example device list
    test_devices = [
        {
            "deviceId": "med-ecg-001",
            "deviceType": "Medical ECG Monitor",
            "manufacturer": "Philips",
            "firmwareVersion": "2.1.3",
            "softwareVersion": "Linux 4.14.0",
            "osName": "Embedded Linux"
        },
        {
            "deviceId": "router-001",
            "deviceType": "IoT Gateway",
            "manufacturer": "TP-Link",
            "firmwareVersion": "1.0.4",
            "softwareVersion": "OpenWrt 19.07",
            "osName": "OpenWrt"
        }
    ]
    
    # Assess device vulnerabilities
    assessments = await monitoring_agent.assess_device_vulnerabilities(test_devices)
    print(f"Completed vulnerability assessment for {len(assessments)} devices")
    
    for assessment in assessments:
        print(f"\nDevice: {assessment.device_id}")
        print(f"Risk Score: {assessment.risk_score:.1f}/10")
        print(f"CVE Matches: {len(assessment.cve_matches)}")
        print("Top Recommendations:")
        for rec in assessment.recommendations[:3]:
            print(f"  - {rec}")

if __name__ == "__main__":
    asyncio.run(main())