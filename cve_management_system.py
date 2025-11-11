"""
CVE Management System for Medical IoT Security Operations Center
Handles CVE data fetching, storage, analysis, and update recommendations
"""

import sqlite3
import json
import logging
import asyncio
import aiohttp
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CVEEntry:
    """CVE vulnerability entry"""
    cve_id: str
    published_date: str
    modified_date: str
    description: str
    severity_score: float  # CVSS score 0-10
    severity_level: str    # LOW, MEDIUM, HIGH, CRITICAL
    affected_systems: List[str]  # List of affected OS/software
    attack_vector: str     # NETWORK, ADJACENT, LOCAL, PHYSICAL
    exploit_available: bool
    patch_available: bool
    patch_complexity: str  # LOW, MEDIUM, HIGH
    business_impact: str   # LOW, MEDIUM, HIGH, CRITICAL
    affected_devices: List[str]  # List of device IDs that are affected
    
@dataclass
class UpdateRecommendation:
    """ML-based update recommendation"""
    cve_id: str
    device_id: str
    recommended_update_time: str
    urgency_score: float   # 0-100
    maintenance_window: Dict[str, str]  # start/end times
    risk_if_delayed: float  # 0-100
    predicted_downtime: int  # minutes
    confidence_score: float  # ML model confidence

class CVEDatabase:
    """Database manager for CVE data"""
    
    def __init__(self, db_path: str = "data/cve_database.db"):
        self.db_path = db_path
        Path("data").mkdir(exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize CVE database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # CVE entries table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    published_date TEXT,
                    modified_date TEXT,
                    description TEXT,
                    severity_score REAL,
                    severity_level TEXT,
                    affected_systems TEXT,
                    attack_vector TEXT,
                    exploit_available BOOLEAN,
                    patch_available BOOLEAN,
                    patch_complexity TEXT,
                    business_impact TEXT,
                    affected_devices TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Update recommendations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS update_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    device_id TEXT,
                    recommended_update_time TEXT,
                    urgency_score REAL,
                    maintenance_window TEXT,
                    risk_if_delayed REAL,
                    predicted_downtime INTEGER,
                    confidence_score REAL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cve_entries (cve_id)
                )
            """)
            
            # Device vulnerability status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_vulnerability_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    cve_id TEXT,
                    status TEXT, -- vulnerable, patched, mitigated, ignored
                    last_scan_date TEXT,
                    patch_applied_date TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cve_entries (cve_id)
                )
            """)
            
            # Device usage patterns for ML
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_usage_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    timestamp TEXT,
                    cpu_usage REAL,
                    memory_usage REAL,
                    network_activity REAL,
                    critical_operations_active BOOLEAN,
                    maintenance_window_active BOOLEAN,
                    patient_connected BOOLEAN,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            logger.info("CVE database initialized successfully")
    
    def store_cve(self, cve: CVEEntry):
        """Store CVE entry in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, published_date, modified_date, description, severity_score,
                 severity_level, affected_systems, attack_vector, exploit_available,
                 patch_available, patch_complexity, business_impact, affected_devices)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve.cve_id, cve.published_date, cve.modified_date, cve.description,
                cve.severity_score, cve.severity_level, json.dumps(cve.affected_systems),
                cve.attack_vector, cve.exploit_available, cve.patch_available,
                cve.patch_complexity, cve.business_impact, json.dumps(cve.affected_devices)
            ))
            conn.commit()
    
    def get_active_cves(self, severity_filter: Optional[str] = None) -> List[Dict]:
        """Get active CVEs with optional severity filter"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM cve_entries"
            params = []
            
            if severity_filter:
                query += " WHERE severity_level = ?"
                params.append(severity_filter)
            
            query += " ORDER BY severity_score DESC, published_date DESC"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def store_update_recommendation(self, recommendation: UpdateRecommendation):
        """Store ML-based update recommendation"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO update_recommendations 
                (cve_id, device_id, recommended_update_time, urgency_score,
                 maintenance_window, risk_if_delayed, predicted_downtime, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                recommendation.cve_id, recommendation.device_id, 
                recommendation.recommended_update_time, recommendation.urgency_score,
                json.dumps(recommendation.maintenance_window), recommendation.risk_if_delayed,
                recommendation.predicted_downtime, recommendation.confidence_score
            ))
            conn.commit()

class CVETimeSeriesAnalyzer:
    """ML-based time series analyzer for optimal update scheduling"""
    
    def __init__(self, db: CVEDatabase):
        self.db = db
        self.model = RandomForestRegressor(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def generate_training_data(self, device_ids: List[str]) -> pd.DataFrame:
        """Generate synthetic training data for ML model"""
        np.random.seed(42)
        
        # Generate 30 days of hourly data for each device
        data = []
        
        for device_id in device_ids:
            for day in range(30):
                for hour in range(24):
                    timestamp = datetime.now() - timedelta(days=29-day, hours=23-hour)
                    
                    # Simulate realistic usage patterns
                    if 6 <= hour <= 22:  # Daytime - higher usage
                        cpu_usage = np.random.normal(60, 15)
                        memory_usage = np.random.normal(70, 10)
                        network_activity = np.random.normal(40, 20)
                        critical_ops = np.random.choice([True, False], p=[0.3, 0.7])
                        patient_connected = np.random.choice([True, False], p=[0.6, 0.4])
                    else:  # Nighttime - lower usage
                        cpu_usage = np.random.normal(25, 10)
                        memory_usage = np.random.normal(30, 8)
                        network_activity = np.random.normal(10, 5)
                        critical_ops = np.random.choice([True, False], p=[0.1, 0.9])
                        patient_connected = np.random.choice([True, False], p=[0.2, 0.8])
                    
                    # Maintenance windows (2-6 AM)
                    maintenance_window = 2 <= hour <= 6
                    
                    # Calculate optimal update score (target variable)
                    # Higher score = better time for updates
                    update_score = 0
                    if maintenance_window:
                        update_score += 40
                    if not critical_ops:
                        update_score += 25
                    if not patient_connected:
                        update_score += 20
                    if cpu_usage < 40:
                        update_score += 10
                    if memory_usage < 50:
                        update_score += 5
                    
                    # Add some noise
                    update_score += np.random.normal(0, 5)
                    update_score = max(0, min(100, update_score))
                    
                    data.append({
                        'device_id': device_id,
                        'timestamp': timestamp.isoformat(),
                        'hour': hour,
                        'day_of_week': timestamp.weekday(),
                        'cpu_usage': max(0, min(100, cpu_usage)),
                        'memory_usage': max(0, min(100, memory_usage)),
                        'network_activity': max(0, min(100, network_activity)),
                        'critical_operations_active': critical_ops,
                        'maintenance_window_active': maintenance_window,
                        'patient_connected': patient_connected,
                        'update_score': update_score
                    })
        
        return pd.DataFrame(data)
    
    def train_model(self, device_ids: List[str]):
        """Train ML model on device usage patterns"""
        logger.info("Training ML model for optimal update scheduling...")
        
        # Generate training data
        df = self.generate_training_data(device_ids)
        
        # Prepare features
        features = ['hour', 'day_of_week', 'cpu_usage', 'memory_usage', 
                   'network_activity', 'critical_operations_active', 
                   'maintenance_window_active', 'patient_connected']
        
        X = df[features].copy()
        X['critical_operations_active'] = X['critical_operations_active'].astype(int)
        X['maintenance_window_active'] = X['maintenance_window_active'].astype(int)
        X['patient_connected'] = X['patient_connected'].astype(int)
        
        y = df['update_score']
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        logger.info(f"ML model trained on {len(df)} data points")
        logger.info(f"Model score: {self.model.score(X_scaled, y):.3f}")
    
    def predict_optimal_update_time(self, device_id: str, cve: CVEEntry) -> UpdateRecommendation:
        """Predict optimal update time for a device and CVE"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        # Generate next 7 days of hourly predictions
        predictions = []
        current_time = datetime.now()
        
        for hours_ahead in range(168):  # 7 days * 24 hours
            future_time = current_time + timedelta(hours=hours_ahead)
            hour = future_time.hour
            day_of_week = future_time.weekday()
            
            # Simulate current device state (would be real data in production)
            if 6 <= hour <= 22:
                cpu_usage = np.random.normal(60, 15)
                memory_usage = np.random.normal(70, 10)
                network_activity = np.random.normal(40, 20)
                critical_ops = np.random.choice([True, False], p=[0.3, 0.7])
                patient_connected = np.random.choice([True, False], p=[0.6, 0.4])
            else:
                cpu_usage = np.random.normal(25, 10)
                memory_usage = np.random.normal(30, 8)
                network_activity = np.random.normal(10, 5)
                critical_ops = np.random.choice([True, False], p=[0.1, 0.9])
                patient_connected = np.random.choice([True, False], p=[0.2, 0.8])
            
            maintenance_window = 2 <= hour <= 6
            
            # Prepare features for prediction
            features = np.array([[
                hour, day_of_week, 
                max(0, min(100, cpu_usage)),
                max(0, min(100, memory_usage)),
                max(0, min(100, network_activity)),
                int(critical_ops),
                int(maintenance_window),
                int(patient_connected)
            ]])
            
            features_scaled = self.scaler.transform(features)
            update_score = self.model.predict(features_scaled)[0]
            
            predictions.append({
                'datetime': future_time,
                'update_score': update_score,
                'critical_ops': critical_ops,
                'maintenance_window': maintenance_window
            })
        
        # Find best update time
        best_prediction = max(predictions, key=lambda x: x['update_score'])
        
        # Calculate urgency based on CVE severity and exploit availability
        urgency_score = (cve.severity_score * 10)  # 0-100
        if cve.exploit_available:
            urgency_score += 20
        if cve.attack_vector == "NETWORK":
            urgency_score += 15
        urgency_score = min(100, urgency_score)
        
        # Calculate risk if delayed
        risk_if_delayed = urgency_score * 0.8  # Risk correlates with urgency
        
        # Predict downtime based on patch complexity
        downtime_map = {"LOW": 15, "MEDIUM": 45, "HIGH": 120}
        predicted_downtime = downtime_map.get(cve.patch_complexity, 45)
        
        # Set maintenance window around optimal time
        optimal_time = best_prediction['datetime']
        maintenance_start = optimal_time - timedelta(minutes=30)
        maintenance_end = optimal_time + timedelta(hours=2)
        
        return UpdateRecommendation(
            cve_id=cve.cve_id,
            device_id=device_id,
            recommended_update_time=optimal_time.isoformat(),
            urgency_score=urgency_score,
            maintenance_window={
                "start": maintenance_start.strftime("%Y-%m-%d %H:%M"),
                "end": maintenance_end.strftime("%Y-%m-%d %H:%M")
            },
            risk_if_delayed=risk_if_delayed,
            predicted_downtime=predicted_downtime,
            confidence_score=best_prediction['update_score']
        )

class NVDCVEFetcher:
    """Fetches CVE data from NIST National Vulnerability Database with API key support"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.session = None
        
        if not self.api_key:
            logger.warning("⚠️  NVD API key not provided. Using rate-limited public access (50 requests per 30 seconds).")
            logger.info("📋 To get unlimited access:")
            logger.info("   1. Register for a free API key at: https://nvd.nist.gov/developers/request-an-api-key")
            logger.info("   2. Set environment variable: NVD_API_KEY=your_api_key")
            logger.info("   3. Or pass it to the constructor: NVDCVEFetcher(api_key='your_key')")
        else:
            logger.info("✅ NVD API key provided. Using unlimited access.")
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for NVD API requests"""
        headers = {
            'User-Agent': 'Medical-IoT-CVE-Manager/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
            
        return headers
    
    async def fetch_recent_cves(self, days: int = 7, keywords: List[str] = None) -> List[CVEEntry]:
        """
        Fetch recent CVEs from NVD API
        
        Args:
            days: Number of days back to search
            keywords: Keywords to filter CVEs (e.g., ['medical', 'iot', 'firmware'])
        """
        if not self.session:
            raise RuntimeError("Must use within async context manager")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Prepare API parameters
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 100,  # Max allowed
            'startIndex': 0
        }
        
        # Add keyword filter if provided
        if keywords:
            # NVD API uses keywordSearch parameter
            params['keywordSearch'] = ' OR '.join(keywords)
        
        cves = []
        total_results = None
        
        try:
            while True:
                logger.info(f"Fetching CVEs from NVD API (offset: {params['startIndex']})...")
                
                async with self.session.get(
                    self.base_url, 
                    params=params, 
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    if response.status == 429:
                        logger.warning("Rate limit exceeded. Waiting 30 seconds...")
                        await asyncio.sleep(30)
                        continue
                    
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"NVD API error {response.status}: {error_text}")
                        break
                    
                    data = await response.json()
                    
                    if total_results is None:
                        total_results = data.get('totalResults', 0)
                        logger.info(f"Total CVEs available: {total_results}")
                    
                    # Process CVEs from this batch
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln_data in vulnerabilities:
                        cve_data = vuln_data.get('cve', {})
                        cve_entry = self._parse_nvd_cve(cve_data)
                        if cve_entry:
                            cves.append(cve_entry)
                    
                    # Check if we have more results
                    if len(vulnerabilities) < params['resultsPerPage']:
                        break
                    
                    params['startIndex'] += params['resultsPerPage']
                    
                    # Respect rate limits (50 requests per 30 seconds without API key)
                    if not self.api_key:
                        await asyncio.sleep(0.6)  # ~1 request per 600ms
                
        except asyncio.TimeoutError:
            logger.error("Timeout while fetching CVE data from NVD")
        except Exception as e:
            logger.error(f"Error fetching CVE data: {e}")
        
        logger.info(f"Successfully fetched {len(cves)} CVEs from NVD")
        return cves
    
    def _parse_nvd_cve(self, cve_data: Dict) -> Optional[CVEEntry]:
        """Parse NVD CVE data into our CVEEntry format"""
        try:
            cve_id = cve_data.get('id', '')
            if not cve_id:
                return None
            
            # Get publication date
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', published)
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS scores
            metrics = cve_data.get('metrics', {})
            severity_score = 0.0
            severity_level = "LOW"
            attack_vector = "UNKNOWN"
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]  # Take first metric
                    cvss_data = metric.get('cvssData', {})
                    
                    if version.startswith('cvssMetricV3'):
                        severity_score = cvss_data.get('baseScore', 0.0)
                        severity_level = cvss_data.get('baseSeverity', 'LOW')
                        attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    else:  # CVSS v2
                        severity_score = cvss_data.get('baseScore', 0.0)
                        if severity_score >= 7.0:
                            severity_level = "HIGH"
                        elif severity_score >= 4.0:
                            severity_level = "MEDIUM"
                        else:
                            severity_level = "LOW"
                        attack_vector = cvss_data.get('accessVector', 'UNKNOWN')
                    break
            
            # Get affected configurations/systems
            affected_systems = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        if cpe.get('vulnerable', False):
                            cpe_name = cpe.get('criteria', '')
                            # Parse CPE name to get readable system name
                            if cpe_name.startswith('cpe:2.3:'):
                                parts = cpe_name.split(':')
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                                    system_name = f"{vendor} {product}"
                                    if version:
                                        system_name += f" {version}"
                                    affected_systems.append(system_name)
            
            # Determine if this affects medical/IoT devices
            affected_devices = []
            medical_keywords = ['medical', 'hospital', 'patient', 'healthcare', 'clinical', 'diagnostic']
            iot_keywords = ['iot', 'embedded', 'firmware', 'device', 'sensor', 'monitor']
            
            description_lower = description.lower()
            systems_text = ' '.join(affected_systems).lower()
            
            if any(keyword in description_lower or keyword in systems_text for keyword in medical_keywords + iot_keywords):
                # This CVE affects medical/IoT devices - assign to sample devices
                affected_devices = ["med-ecg-001", "med-pump-002", "med-monitor-003"][:1]  # Assign to one device initially
            
            # Determine patch availability (simplified logic)
            patch_available = any('patch' in ref.get('url', '').lower() for ref in cve_data.get('references', []))
            
            # Determine exploit availability (simplified logic)
            exploit_available = any('exploit' in ref.get('url', '').lower() for ref in cve_data.get('references', []))
            
            return CVEEntry(
                cve_id=cve_id,
                published_date=published,
                modified_date=modified,
                description=description,
                severity_score=severity_score,
                severity_level=severity_level.upper(),
                affected_systems=affected_systems[:5],  # Limit to first 5
                attack_vector=attack_vector.upper(),
                exploit_available=exploit_available,
                patch_available=patch_available,
                patch_complexity="MEDIUM",  # Default
                business_impact="HIGH" if severity_score >= 7.0 else "MEDIUM" if severity_score >= 4.0 else "LOW",
                affected_devices=affected_devices
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVE {cve_data.get('id', 'unknown')}: {e}")
            return None

class CVEManager:
    """Main CVE management system"""
    
    def __init__(self):
        self.db = CVEDatabase()
        self.analyzer = CVETimeSeriesAnalyzer(self.db)
        self.device_ids = []
    
    async def initialize(self, device_ids: List[str]):
        """Initialize CVE manager with device list"""
        self.device_ids = device_ids
        logger.info(f"Initializing CVE manager for {len(device_ids)} devices")
        
        # Train ML model
        self.analyzer.train_model(device_ids)
        
        # Fetch real CVE data from NVD (falls back to samples if unavailable)
        await self.fetch_and_store_cves()
        
        logger.info("CVE Manager initialized successfully")
    
    async def fetch_and_store_cves(self):
        """Fetch CVE data from trusted sources"""
        try:
            async with NVDCVEFetcher() as nvd_fetcher:
                # Fetch recent CVEs with medical/IoT keywords
                medical_iot_keywords = [
                    'medical', 'healthcare', 'hospital', 'patient', 'clinical',
                    'iot', 'embedded', 'firmware', 'device', 'sensor', 'monitor'
                ]
                
                logger.info("🔍 Fetching real CVE data from NIST NVD...")
                real_cves = await nvd_fetcher.fetch_recent_cves(
                    days=30,  # Last 30 days
                    keywords=medical_iot_keywords
                )
                
                # Store real CVEs in database
                for cve in real_cves:
                    self.db.store_cve(cve)
                
                if real_cves:
                    logger.info(f"✅ Successfully loaded {len(real_cves)} real CVEs from NVD")
                else:
                    logger.warning("⚠️ No relevant CVEs found, using sample data for demonstration")
                    await self.generate_sample_cves()
                    
        except Exception as e:
            logger.error(f"❌ Failed to fetch real CVE data: {e}")
            logger.info("🔄 Falling back to sample CVE data...")
            await self.generate_sample_cves()
    
    async def fetch_real_cves_from_nvd(self):
        """Fetch real CVE data from NIST NVD API"""
        try:
            # NIST NVD API endpoint for recent CVEs
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Get CVEs from the last 30 days that might affect medical devices
            from datetime import datetime, timedelta
            start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
            
            params = {
                "pubStartDate": start_date,
                "resultsPerPage": 20,
                "keywordSearch": "medical device OR healthcare OR IoT OR network OR firmware OR remote",
                "cvssV3Severity": "HIGH,CRITICAL"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.parse_nvd_response(data)
                    else:
                        logger.warning(f"NVD API returned status {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Failed to fetch CVEs from NVD: {e}")
            return []

    def parse_nvd_response(self, nvd_data):
        """Parse NVD API response into CVEEntry objects"""
        cves = []
        
        for vulnerability in nvd_data.get('vulnerabilities', []):
            cve_data = vulnerability.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            
            # Extract basic info
            published = cve_data.get('published', datetime.now().isoformat())
            modified = cve_data.get('lastModified', published)
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = "No description available"
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            
            # Extract CVSS score
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity_level = "LOW"
            attack_vector = "UNKNOWN"
            
            # Try CVSS v3.1 first, then v3.0
            for cvss_version in ['cvssMetricV31', 'cvssMetricV30']:
                if cvss_version in metrics:
                    cvss_data = metrics[cvss_version][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    
                    # Determine severity level
                    if cvss_score >= 9.0:
                        severity_level = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity_level = "HIGH"
                    elif cvss_score >= 4.0:
                        severity_level = "MEDIUM"
                    else:
                        severity_level = "LOW"
                    break
            
            # Extract affected systems from CPE data
            affected_systems = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_name = cpe_match.get('criteria', '')
                        if cpe_name:
                            # Parse CPE name to extract readable system info
                            parts = cpe_name.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else '*'
                                system_name = f"{vendor.title()} {product.title()}"
                                if version != '*':
                                    system_name += f" {version}"
                                if system_name not in affected_systems:
                                    affected_systems.append(system_name)
            
            # If no specific systems found, infer from description
            if not affected_systems:
                desc_lower = description.lower()
                if any(term in desc_lower for term in ['linux', 'kernel']):
                    affected_systems.append("Linux System")
                if any(term in desc_lower for term in ['windows', 'microsoft']):
                    affected_systems.append("Windows System")
                if any(term in desc_lower for term in ['medical', 'healthcare', 'device']):
                    affected_systems.append("Medical Device Software")
                if any(term in desc_lower for term in ['network', 'protocol', 'tcp', 'udp']):
                    affected_systems.append("Network Protocol Stack")
                if not affected_systems:
                    affected_systems.append("Unknown System")
            
            # Determine which devices might be affected based on CVE characteristics
            affected_devices = []
            desc_lower = description.lower()
            
            # Match devices based on CVE description and severity
            if any(term in desc_lower for term in ['cardiac', 'heart', 'ecg', 'ekg']):
                affected_devices.append("med-ecg-001")
            if any(term in desc_lower for term in ['pump', 'infusion', 'medication']):
                affected_devices.append("med-pump-002")
            if any(term in desc_lower for term in ['monitor', 'vital', 'patient']):
                affected_devices.append("med-monitor-003")
            if any(term in desc_lower for term in ['ventilator', 'breathing', 'respiratory']):
                affected_devices.append("med-ventilator-004")
            if any(term in desc_lower for term in ['scan', 'imaging', 'mri', 'ct']):
                affected_devices.append("med-scanner-005")
            
            # If high/critical severity and network-related, likely affects all network-connected devices
            if severity_level in ["HIGH", "CRITICAL"] and attack_vector == "NETWORK":
                affected_devices = self.device_ids
            elif not affected_devices:
                # Default assignment based on severity
                if severity_level == "CRITICAL":
                    affected_devices = self.device_ids[:3]
                elif severity_level == "HIGH":
                    affected_devices = self.device_ids[:2]
                else:
                    affected_devices = [self.device_ids[0]]
            
            # Check for patch availability (inferred from publication date)
            days_since_published = (datetime.now() - datetime.fromisoformat(published.replace('Z', '+00:00'))).days
            patch_available = days_since_published > 14  # Assume patches available after 14 days
            
            # Check for exploit availability (heuristic based on CVSS and time)
            exploit_available = cvss_score >= 8.5 and days_since_published > 7
            
            # Determine patch complexity
            patch_complexity = "HIGH" if "firmware" in description.lower() or "kernel" in description.lower() else "MEDIUM"
            if "configuration" in description.lower() or "setting" in description.lower():
                patch_complexity = "LOW"
            
            # Business impact
            business_impact = severity_level
            
            cve_entry = CVEEntry(
                cve_id=cve_id,
                published_date=published,
                modified_date=modified,
                description=description,
                severity_score=cvss_score,
                severity_level=severity_level,
                affected_systems=affected_systems,
                attack_vector=attack_vector,
                exploit_available=exploit_available,
                patch_available=patch_available,
                patch_complexity=patch_complexity,
                business_impact=business_impact,
                affected_devices=affected_devices
            )
            
            cves.append(cve_entry)
        
        return cves

    async def generate_sample_cves(self):
        """Fetch real CVE data from NVD, fallback to samples if unavailable"""
        logger.info("Fetching real CVE data from NIST NVD...")
        
        # Try to fetch real CVEs first
        real_cves = await self.fetch_real_cves_from_nvd()
        
        if real_cves:
            logger.info(f"Successfully fetched {len(real_cves)} real CVEs from NVD")
            # Store real CVEs in database
            for cve in real_cves:
                self.db.store_cve(cve)
            return
        
        # Fallback to sample data if NVD is unavailable
        logger.warning("NVD unavailable, using sample CVE data")
        sample_cves = [
            CVEEntry(
                cve_id="CVE-2024-0001",
                published_date="2024-09-20T08:00:00Z",
                modified_date="2024-09-21T10:30:00Z",
                description="Critical buffer overflow in medical device firmware allowing remote code execution",
                severity_score=9.8,
                severity_level="CRITICAL",
                affected_systems=["Linux Kernel 5.4", "Medical Device Firmware v2.1"],
                attack_vector="NETWORK",
                exploit_available=True,
                patch_available=True,
                patch_complexity="MEDIUM",
                business_impact="CRITICAL",
                affected_devices=self.device_ids[:3]
            ),
            CVEEntry(
                cve_id="CVE-2024-0002",
                published_date="2024-09-19T14:22:00Z",
                modified_date="2024-09-19T14:22:00Z",
                description="SQL injection vulnerability in device management web interface",
                severity_score=7.5,
                severity_level="HIGH",
                affected_systems=["Web Interface v3.2", "PostgreSQL 12.x"],
                attack_vector="NETWORK",
                exploit_available=False,
                patch_available=True,
                patch_complexity="LOW",
                business_impact="HIGH",
                affected_devices=self.device_ids[1:4]
            ),
            CVEEntry(
                cve_id="CVE-2024-0003",
                published_date="2024-09-18T11:15:00Z",
                modified_date="2024-09-20T16:45:00Z",
                description="Privilege escalation in Windows service component",
                severity_score=6.8,
                severity_level="MEDIUM",
                affected_systems=["Windows 10", "Windows 11", "Device Service v1.5"],
                attack_vector="LOCAL",
                exploit_available=False,
                patch_available=True,
                patch_complexity="HIGH",
                business_impact="MEDIUM",
                affected_devices=self.device_ids[2:5]
            ),
            CVEEntry(
                cve_id="CVE-2024-0004",
                published_date="2024-09-17T09:30:00Z",
                modified_date="2024-09-17T09:30:00Z",
                description="Information disclosure through unencrypted log files",
                severity_score=4.3,
                severity_level="MEDIUM",
                affected_systems=["Logging Service v2.0", "File System"],
                attack_vector="LOCAL",
                exploit_available=False,
                patch_available=True,
                patch_complexity="LOW",
                business_impact="LOW",
                affected_devices=self.device_ids[:2]
            ),
            CVEEntry(
                cve_id="CVE-2024-0005",
                published_date="2024-09-21T12:00:00Z",
                modified_date="2024-09-21T15:20:00Z",
                description="Zero-day RCE in network communication protocol",
                severity_score=9.9,
                severity_level="CRITICAL",
                affected_systems=["Network Protocol Stack", "Communication Module"],
                attack_vector="NETWORK",
                exploit_available=True,
                patch_available=False,
                patch_complexity="HIGH",
                business_impact="CRITICAL",
                affected_devices=self.device_ids
            )
        ]
        
        # Store sample CVEs in database
        for cve in sample_cves:
            self.db.store_cve(cve)
        
        logger.info(f"Generated {len(sample_cves)} sample CVEs")

    async def update_cve_data_from_sources(self):
        """Update CVE data from multiple trusted sources"""
        logger.info("Updating CVE data from trusted sources...")
        
        # Primary source: NIST NVD
        nvd_cves = await self.fetch_real_cves_from_nvd()
        
        # You can add more sources here:
        # - MITRE CVE database
        # - ICS-CERT advisories for medical devices
        # - Vendor-specific security advisories
        
        all_new_cves = nvd_cves
        
        if all_new_cves:
            logger.info(f"Updating database with {len(all_new_cves)} CVEs from trusted sources")
            for cve in all_new_cves:
                self.db.store_cve(cve)
            return len(all_new_cves)
        else:
            logger.warning("No new CVEs retrieved from trusted sources")
            return 0

    async def fetch_medical_device_cves(self):
        """Fetch CVEs specifically related to medical devices and healthcare"""
        try:
            # Search for medical device specific CVEs
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            medical_keywords = [
                "medical device",
                "healthcare",
                "hospital",
                "patient monitor",
                "infusion pump",
                "ventilator",
                "defibrillator",
                "pacemaker",
                "imaging system",
                "EHR",
                "EMR",
                "DICOM",
                "HL7"
            ]
            
            all_medical_cves = []
            
            for keyword in medical_keywords[:3]:  # Limit to avoid rate limiting
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 10,
                    "cvssV3Severity": "MEDIUM,HIGH,CRITICAL"
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            medical_cves = self.parse_nvd_response(data)
                            all_medical_cves.extend(medical_cves)
                            
                            # Add small delay to respect rate limits
                            await asyncio.sleep(1)
                        else:
                            logger.warning(f"NVD API returned status {response.status} for keyword: {keyword}")
            
            # Remove duplicates based on CVE ID
            unique_cves = {}
            for cve in all_medical_cves:
                unique_cves[cve.cve_id] = cve
            
            return list(unique_cves.values())
            
        except Exception as e:
            logger.error(f"Failed to fetch medical device CVEs: {e}")
            return []
    
    async def get_cve_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive CVE dashboard data"""
        active_cves = self.db.get_active_cves()
        
        # Generate update recommendations for each CVE-device combination
        recommendations = []
        for cve_data in active_cves:
            cve = CVEEntry(
                cve_id=cve_data['cve_id'],
                published_date=cve_data['published_date'],
                modified_date=cve_data['modified_date'],
                description=cve_data['description'],
                severity_score=cve_data['severity_score'],
                severity_level=cve_data['severity_level'],
                affected_systems=json.loads(cve_data['affected_systems']),
                attack_vector=cve_data['attack_vector'],
                exploit_available=bool(cve_data['exploit_available']),
                patch_available=bool(cve_data['patch_available']),
                patch_complexity=cve_data['patch_complexity'],
                business_impact=cve_data['business_impact'],
                affected_devices=json.loads(cve_data['affected_devices'])
            )
            
            for device_id in cve.affected_devices:
                if device_id in self.device_ids:
                    try:
                        recommendation = self.analyzer.predict_optimal_update_time(device_id, cve)
                        recommendations.append(asdict(recommendation))
                        self.db.store_update_recommendation(recommendation)
                    except Exception as e:
                        logger.error(f"Failed to generate recommendation for {cve.cve_id}-{device_id}: {e}")
        
        # Calculate summary statistics
        total_cves = len(active_cves)
        critical_cves = len([c for c in active_cves if c['severity_level'] == 'CRITICAL'])
        high_cves = len([c for c in active_cves if c['severity_level'] == 'HIGH'])
        exploitable_cves = len([c for c in active_cves if c['exploit_available']])
        
        return {
            "summary": {
                "total_cves": total_cves,
                "critical_cves": critical_cves,
                "high_severity_cves": high_cves,
                "exploitable_cves": exploitable_cves,
                "affected_devices": len(set([d for cve in active_cves for d in json.loads(cve['affected_devices'])]))
            },
            "cves": active_cves,
            "recommendations": recommendations,
            "last_updated": datetime.now().isoformat()
        }

# Global CVE manager instance
cve_manager = None

async def get_cve_manager() -> CVEManager:
    """Get or create CVE manager singleton"""
    global cve_manager
    if cve_manager is None:
        cve_manager = CVEManager()
        # Initialize with sample device IDs
        device_ids = ["med-ecg-001", "med-pump-002", "med-monitor-003", "med-ventilator-004", "med-scanner-005"]
        await cve_manager.initialize(device_ids)
    return cve_manager

if __name__ == "__main__":
    async def main():
        manager = await get_cve_manager()
        dashboard_data = await manager.get_cve_dashboard_data()
        print(json.dumps(dashboard_data, indent=2))
    
    asyncio.run(main())