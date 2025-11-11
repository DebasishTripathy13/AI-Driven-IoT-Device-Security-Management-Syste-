"""
Comprehensive Database Manager for Medical IoT Device Management System
Handles all logging, analytics, geographic data, and security events
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import threading
from dataclasses import dataclass
from pathlib import Path
import requests
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class APIRequest:
    """Data class for API request logging"""
    timestamp: float
    ip_address: str
    method: str
    path: str
    status_code: int
    processing_time: float
    user_agent: str
    request_size: int
    response_size: int
    country: str = "Unknown"
    city: str = "Unknown"
    threat_level: str = "normal"
    blocked: bool = False

@dataclass
class SecurityEvent:
    """Data class for security events"""
    timestamp: float
    ip_address: str
    event_type: str
    severity: str
    description: str
    action_taken: str
    details: Dict[str, Any]

class DatabaseManager:
    """Comprehensive database manager for the application"""
    
    def __init__(self, db_path: str = "data/application.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize database with all required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # API Requests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    ip_address TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    processing_time REAL NOT NULL,
                    user_agent TEXT,
                    request_size INTEGER DEFAULT 0,
                    response_size INTEGER DEFAULT 0,
                    country TEXT DEFAULT 'Unknown',
                    city TEXT DEFAULT 'Unknown',
                    threat_level TEXT DEFAULT 'normal',
                    blocked BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Security Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    ip_address TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Blocked IPs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL,
                    blocked_at REAL NOT NULL,
                    expires_at REAL,
                    request_count INTEGER DEFAULT 1,
                    threat_level TEXT DEFAULT 'medium',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Geographic Data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS geographic_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    country TEXT NOT NULL,
                    city TEXT NOT NULL,
                    latitude REAL,
                    longitude REAL,
                    last_seen REAL NOT NULL,
                    request_count INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Application Logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS application_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_requests_timestamp ON api_requests(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_requests_ip ON api_requests(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_geographic_ip ON geographic_data(ip_address)")
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    def get_ip_geolocation(self, ip_address: str) -> Dict[str, str]:
        """Get geographic information for an IP address"""
        if ip_address in ['127.0.0.1', '::1', 'localhost']:
            return {'country': 'Local Host', 'city': 'localhost'}
        
        try:
            # Use a free geolocation service (in production, use a proper service)
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
        except Exception as e:
            logger.debug(f"Failed to get geolocation for {ip_address}: {e}")
        
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    def log_api_request(self, request_data: APIRequest):
        """Log an API request to the database"""
        with self._lock:
            try:
                # Get geographic data if not provided
                if request_data.country == "Unknown":
                    geo_data = self.get_ip_geolocation(request_data.ip_address)
                    request_data.country = geo_data.get('country', 'Unknown')
                    request_data.city = geo_data.get('city', 'Unknown')
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO api_requests 
                        (timestamp, ip_address, method, path, status_code, processing_time, 
                         user_agent, request_size, response_size, country, city, threat_level, blocked)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        request_data.timestamp, request_data.ip_address, request_data.method,
                        request_data.path, request_data.status_code, request_data.processing_time,
                        request_data.user_agent, request_data.request_size, request_data.response_size,
                        request_data.country, request_data.city, request_data.threat_level, request_data.blocked
                    ))
                    
                    # Update geographic data
                    cursor.execute("""
                        INSERT OR REPLACE INTO geographic_data 
                        (ip_address, country, city, last_seen, request_count)
                        VALUES (?, ?, ?, ?, 
                            COALESCE((SELECT request_count FROM geographic_data WHERE ip_address = ?), 0) + 1)
                    """, (request_data.ip_address, request_data.country, request_data.city, 
                          request_data.timestamp, request_data.ip_address))
                    
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to log API request: {e}")
    
    def log_security_event(self, event_type: str = None, severity: str = None, description: str = None, 
                          source_ip: str = None, additional_data: Dict[str, Any] = None, event: SecurityEvent = None):
        """Log a security event to the database (supports both new and old signatures)"""
        with self._lock:
            try:
                if event is not None:
                    # Old signature with SecurityEvent object
                    timestamp = event.timestamp
                    ip_address = event.ip_address
                    event_type_val = event.event_type
                    severity_val = event.severity
                    description_val = event.description
                    action_taken = event.action_taken
                    details = event.details
                else:
                    # New signature with individual parameters
                    timestamp = datetime.now().timestamp()
                    ip_address = source_ip or 'unknown'
                    event_type_val = event_type or 'general'
                    severity_val = severity or 'info'
                    description_val = description or 'Security event'
                    action_taken = 'logged'
                    details = additional_data or {}
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO security_events 
                        (timestamp, ip_address, event_type, severity, description, action_taken, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        timestamp, ip_address, event_type_val,
                        severity_val, description_val, action_taken,
                        json.dumps(details) if details else None
                    ))
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
    
    def get_all_security_events(self) -> List[Dict[str, Any]]:
        """Get all security events from the database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT timestamp, ip_address, event_type, severity, description, action_taken, details
                        FROM security_events 
                        ORDER BY timestamp DESC
                        LIMIT 1000
                    """)
                    
                    events = []
                    for row in cursor.fetchall():
                        timestamp, ip_address, event_type, severity, description, action_taken, details = row
                        
                        # Convert timestamp to ISO format
                        dt = datetime.fromtimestamp(timestamp)
                        iso_timestamp = dt.isoformat()
                        
                        event_dict = {
                            'timestamp': iso_timestamp,
                            'ip_address': ip_address,
                            'source_ip': ip_address,  # Alias for compatibility
                            'event_type': event_type,
                            'severity': severity,
                            'description': description,
                            'action_taken': action_taken,
                            'additional_data': json.loads(details) if details else {}
                        }
                        events.append(event_dict)
                    
                    return events
                    
            except Exception as e:
                logger.error(f"Failed to get security events: {e}")
                return []
    
    def block_ip(self, ip_address: str, reason: str, duration_hours: Optional[int] = None):
        """Add an IP to the blocked list"""
        with self._lock:
            try:
                expires_at = None
                if duration_hours:
                    expires_at = datetime.now().timestamp() + (duration_hours * 3600)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO blocked_ips 
                        (ip_address, reason, blocked_at, expires_at, request_count, threat_level)
                        VALUES (?, ?, ?, ?, 
                            COALESCE((SELECT request_count FROM blocked_ips WHERE ip_address = ?), 0) + 1,
                            'high')
                    """, (ip_address, reason, datetime.now().timestamp(), expires_at, ip_address))
                    conn.commit()
                    
                logger.info(f"Blocked IP {ip_address}: {reason}")
                
            except Exception as e:
                logger.error(f"Failed to block IP {ip_address}: {e}")
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT expires_at FROM blocked_ips 
                    WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)
                """, (ip_address, datetime.now().timestamp()))
                return cursor.fetchone() is not None
                
        except Exception as e:
            logger.error(f"Failed to check if IP is blocked: {e}")
            return False
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently blocked IPs"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip_address, reason, blocked_at, expires_at, request_count, threat_level
                    FROM blocked_ips 
                    WHERE expires_at IS NULL OR expires_at > ?
                    ORDER BY blocked_at DESC
                """, (datetime.now().timestamp(),))
                
                blocked_ips = []
                for row in cursor.fetchall():
                    blocked_ips.append({
                        'ip_address': row[0],
                        'reason': row[1],
                        'blocked_at': row[2],
                        'expires_at': row[3],
                        'request_count': row[4],
                        'threat_level': row[5]
                    })
                return blocked_ips
                
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def get_geographic_analysis(self, hours: int = 24) -> Dict[str, Any]:
        """Get geographic distribution of requests"""
        try:
            since_timestamp = (datetime.now() - timedelta(hours=hours)).timestamp()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT country, city, COUNT(*) as request_count, 
                           MAX(timestamp) as last_request
                    FROM api_requests 
                    WHERE timestamp > ? AND country != 'Unknown'
                    GROUP BY country, city
                    ORDER BY request_count DESC
                """, (since_timestamp,))
                
                geographic_data = []
                total_requests = 0
                
                # Country flag mapping
                country_flags = {
                    'United States': '🇺🇸', 'India': '🇮🇳', 'Germany': '🇩🇪',
                    'United Kingdom': '🇬🇧', 'Japan': '🇯🇵', 'Canada': '🇨🇦',
                    'Australia': '🇦🇺', 'France': '🇫🇷', 'Brazil': '🇧🇷',
                    'Singapore': '🇸🇬', 'Local Host': '🏠', 'Unknown': '❓'
                }
                
                for row in cursor.fetchall():
                    country, city, count, last_request = row
                    total_requests += count
                    
                    geographic_data.append({
                        'country': country,
                        'city': city,
                        'requests': count,
                        'flag': country_flags.get(country, '🌍'),
                        'last_request': last_request,
                        'percentage': 0  # Will be calculated below
                    })
                
                # Calculate percentages
                for item in geographic_data:
                    item['percentage'] = (item['requests'] / max(total_requests, 1)) * 100
                
                return {
                    'geographic_data': geographic_data[:15],
                    'total_countries': len(set(item['country'] for item in geographic_data)),
                    'total_requests': total_requests,
                    'time_period_hours': hours
                }
                
        except Exception as e:
            logger.error(f"Failed to get geographic analysis: {e}")
            return {
                'geographic_data': [],
                'total_countries': 0,
                'total_requests': 0,
                'time_period_hours': hours
            }
    
    def get_request_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive request analytics"""
        try:
            since_timestamp = (datetime.now() - timedelta(hours=hours)).timestamp()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get request type distribution based on actual API endpoints
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN path LIKE '%/telemetry/%' THEN 'telemetry'
                            WHEN (path LIKE '%/devices/connect%' OR path LIKE '%/devices/disconnect%' OR (path LIKE '%/devices%' AND method = 'GET')) THEN 'connect'
                            WHEN path LIKE '%/devices/%/code%' THEN 'code'
                            WHEN (path LIKE '%/devices/%' AND method = 'PATCH') THEN 'patch'
                            WHEN (path LIKE '%/status%' OR path LIKE '%/health%' OR path LIKE '%/devices/%/status%') THEN 'status'
                            WHEN path LIKE '%/messages/%' THEN 'message'
                            ELSE 'other'
                        END as request_type,
                        COUNT(*) as count
                    FROM api_requests 
                    WHERE timestamp > ?
                    GROUP BY request_type
                    ORDER BY count DESC
                """, (since_timestamp,))
                
                request_types = {}
                total_requests = 0
                
                for row in cursor.fetchall():
                    request_type, count = row
                    total_requests += count
                    request_types[request_type] = {
                        'count': count,
                        'percentage': 0
                    }
                
                # Calculate percentages
                for request_type in request_types:
                    request_types[request_type]['percentage'] = (
                        request_types[request_type]['count'] / max(total_requests, 1)
                    ) * 100
                
                # Get recent activities
                cursor.execute("""
                    SELECT id, timestamp, ip_address, method, path, status_code, country, city
                    FROM api_requests 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """, (since_timestamp,))
                
                activities = []
                for row in cursor.fetchall():
                    # Categorize request type based on path and method
                    path = row[4]
                    method = row[3]
                    
                    if '/telemetry/' in path:
                        request_type = 'telemetry'
                    elif '/devices/connect' in path or '/devices/disconnect' in path or ('/devices' in path and method == 'GET'):
                        request_type = 'connect'
                    elif '/devices/' in path and '/code' in path:
                        request_type = 'code'
                    elif '/devices/' in path and method == 'PATCH':
                        request_type = 'patch'
                    elif '/status' in path or '/health' in path or ('/devices/' in path and '/status' in path):
                        request_type = 'status'
                    elif '/messages/' in path:
                        request_type = 'message'
                    else:
                        request_type = 'other'
                    
                    activities.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'ip': row[2],
                        'method': row[3],
                        'path': row[4],
                        'status_code': row[5],
                        'country': row[6],
                        'city': row[7],
                        'type': request_type,
                        'event_type': 'Request'
                    })
                
                return {
                    'categories': request_types,
                    'total_requests': total_requests,
                    'recent_activities': activities,
                    'time_period_hours': hours
                }
                
        except Exception as e:
            logger.error(f"Failed to get request analytics: {e}")
            return {
                'categories': {},
                'total_requests': 0,
                'recent_activities': [],
                'time_period_hours': hours
            }
    
    def log_application_event(self, level: str, component: str, message: str, details: Dict[str, Any] = None):
        """Log application events"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO application_logs 
                        (timestamp, level, component, message, details)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        datetime.now().timestamp(), level, component, message,
                        json.dumps(details) if details else None
                    ))
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to log application event: {e}")
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """Clean up old data from the database"""
        cutoff_timestamp = (datetime.now() - timedelta(days=days_to_keep)).timestamp()
        
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Clean up old API requests
                    cursor.execute("DELETE FROM api_requests WHERE timestamp < ?", (cutoff_timestamp,))
                    
                    # Clean up old security events
                    cursor.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff_timestamp,))
                    
                    # Clean up expired blocked IPs
                    cursor.execute("""
                        DELETE FROM blocked_ips 
                        WHERE expires_at IS NOT NULL AND expires_at < ?
                    """, (datetime.now().timestamp(),))
                    
                    # Clean up old application logs
                    cursor.execute("DELETE FROM application_logs WHERE timestamp < ?", (cutoff_timestamp,))
                    
                    conn.commit()
                    logger.info(f"Cleaned up data older than {days_to_keep} days")
                    
            except Exception as e:
                logger.error(f"Failed to cleanup old data: {e}")

# Create global database manager instance
db_manager = DatabaseManager()

if __name__ == "__main__":
    # Test the database manager
    print("Testing Database Manager...")
    
    # Test API request logging
    test_request = APIRequest(
        timestamp=datetime.now().timestamp(),
        ip_address="127.0.0.1",
        method="GET",
        path="/api/devices",
        status_code=200,
        processing_time=0.05,
        user_agent="Test Client",
        request_size=0,
        response_size=1024
    )
    
    db_manager.log_api_request(test_request)
    
    # Test security event logging
    test_event = SecurityEvent(
        timestamp=datetime.now().timestamp(),
        ip_address="192.168.1.100",
        event_type="suspicious_activity",
        severity="medium",
        description="Multiple failed authentication attempts",
        action_taken="monitoring",
        details={"attempts": 5, "timeframe": "60s"}
    )
    
    db_manager.log_security_event(test_event)
    
    # Test analytics
    analytics = db_manager.get_request_analytics()
    print(f"Analytics: {analytics}")
    
    geo_data = db_manager.get_geographic_analysis()
    print(f"Geographic data: {geo_data}")
    
    print("Database Manager test completed!")