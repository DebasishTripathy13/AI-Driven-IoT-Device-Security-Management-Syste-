"""
Intrusion Detection System (IDS) for Medical IoT API Server
Comprehensive security monitoring with threat detection and IP blocking
"""
import re
import json
import time
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Configure IDS logging
ids_logger = logging.getLogger('ids')
ids_logger.setLevel(logging.INFO)
ids_handler = logging.FileHandler('ids_security.log')
ids_handler.setFormatter(logging.Formatter(
    '%(asctime)s - IDS - %(levelname)s - %(message)s'
))
ids_logger.addHandler(ids_handler)

@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: str
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str
    user_agent: str
    method: str
    path: str
    payload: str
    threat_details: str
    action_taken: str
    event_id: str

@dataclass
class RequestMetrics:
    """Request analytics data"""
    ip: str
    method: str
    path: str
    timestamp: float
    user_agent: str
    payload_size: int
    response_code: int

class ThreatDetector:
    """Advanced threat detection engine"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sqli_patterns = [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(\'\s*or\s*\'\d+\'\s*=\s*\'\d+|\'\s*or\s*\d+\s*=\s*\d+)",
            r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
            r"(?i)(script\s*>|javascript:|vbscript:)",
            r"(?i)(\-\-|\#|\/\*|\*\/)",
            r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
        ]
        
        # Code injection patterns
        self.code_injection_patterns = [
            r"(?i)(eval\s*\(|exec\s*\(|system\s*\(|shell_exec\s*\()",
            r"(?i)(import\s+os|import\s+subprocess|import\s+sys)",
            r"(?i)(__import__|getattr|setattr|delattr)",
            r"(?i)(base64\.decode|urllib\.request|requests\.get)",
            r"(?i)(rm\s+-rf|del\s+/|format\s+c:)",
            r"(?i)(nc\s+-l|netcat|ncat|socat)",
            r"(?i)(powershell|cmd\.exe|/bin/sh|/bin/bash)",
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            r"(?i)(\|\s*[a-z]+|\&\&|\|\||;)",
            r"(?i)(cat\s+/etc/passwd|ls\s+-la|ps\s+aux)",
            r"(?i)(wget\s+|curl\s+|nc\s+|telnet\s+)",
            r"(?i)(\$\(.*\)|`.*`|\$\{.*\})",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)(<script.*?>|</script>|javascript:|vbscript:)",
            r"(?i)(onload=|onerror=|onclick=|onmouseover=)",
            r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
            r"(?i)(document\.cookie|window\.location|document\.write)",
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"(\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c)",
            r"(?i)(etc/passwd|windows/system32|boot\.ini)",
        ]
        
        # Suspicious user agents
        self.suspicious_user_agents = [
            r"(?i)(sqlmap|nmap|nikto|dirb|gobuster|ffuf)",
            r"(?i)(burp|owasp|zap|w3af|acunetix)",
            r"(?i)(python-requests|curl|wget)",
            r"(?i)(bot|crawler|scanner|exploit)",
        ]

    def detect_sqli(self, payload: str) -> Tuple[bool, str]:
        """Detect SQL injection attempts"""
        for pattern in self.sqli_patterns:
            if re.search(pattern, payload):
                return True, f"SQL injection pattern detected: {pattern}"
        return False, ""

    def detect_code_injection(self, payload: str) -> Tuple[bool, str]:
        """Detect code injection attempts"""
        for pattern in self.code_injection_patterns:
            if re.search(pattern, payload):
                return True, f"Code injection pattern detected: {pattern}"
        return False, ""

    def detect_command_injection(self, payload: str) -> Tuple[bool, str]:
        """Detect command injection attempts"""
        for pattern in self.command_injection_patterns:
            if re.search(pattern, payload):
                return True, f"Command injection pattern detected: {pattern}"
        return False, ""

    def detect_xss(self, payload: str) -> Tuple[bool, str]:
        """Detect XSS attempts"""
        for pattern in self.xss_patterns:
            if re.search(pattern, payload):
                return True, f"XSS pattern detected: {pattern}"
        return False, ""

    def detect_path_traversal(self, payload: str) -> Tuple[bool, str]:
        """Detect path traversal attempts"""
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, payload):
                return True, f"Path traversal pattern detected: {pattern}"
        return False, ""

    def detect_suspicious_user_agent(self, user_agent: str) -> Tuple[bool, str]:
        """Detect suspicious user agents"""
        for pattern in self.suspicious_user_agents:
            if re.search(pattern, user_agent):
                return True, f"Suspicious user agent detected: {pattern}"
        return False, ""

    def analyze_payload(self, payload: str, user_agent: str) -> List[Tuple[str, str, str]]:
        """Comprehensive payload analysis"""
        threats = []
        
        # Check for various threats
        checks = [
            ("SQLi", self.detect_sqli(payload)),
            ("Code Injection", self.detect_code_injection(payload)),
            ("Command Injection", self.detect_command_injection(payload)),
            ("XSS", self.detect_xss(payload)),
            ("Path Traversal", self.detect_path_traversal(payload)),
            ("Suspicious User Agent", self.detect_suspicious_user_agent(user_agent)),
        ]
        
        for threat_type, (detected, details) in checks:
            if detected:
                severity = self._get_threat_severity(threat_type)
                threats.append((threat_type, severity, details))
        
        return threats

    def _get_threat_severity(self, threat_type: str) -> str:
        """Determine threat severity level"""
        severity_map = {
            "SQLi": "HIGH",
            "Code Injection": "CRITICAL",
            "Command Injection": "CRITICAL",
            "XSS": "MEDIUM",
            "Path Traversal": "HIGH",
            "Suspicious User Agent": "LOW",
        }
        return severity_map.get(threat_type, "MEDIUM")


class IPBlockManager:
    """Manages IP blocking and rate limiting"""
    
    def __init__(self):
        self.blocked_ips: Dict[str, Dict] = {}
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque())
        self.permanent_blocks: set = set()
        
        # Rate limiting thresholds
        self.flood_threshold = 1000  # requests per minute
        self.flood_window = 60  # seconds
        self.block_duration = 3600  # 1 hour default block
        
    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is currently blocked"""
        if ip in self.permanent_blocks:
            return True, "Permanently blocked"
            
        if ip in self.blocked_ips:
            block_info = self.blocked_ips[ip]
            if time.time() < block_info['expires']:
                return True, block_info['reason']
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]
                
        return False, None
    
    def record_request(self, ip: str) -> bool:
        """Record request and check for flood detection"""
        current_time = time.time()
        
        # Clean old requests outside the window
        requests = self.request_counts[ip]
        while requests and requests[0] < current_time - self.flood_window:
            requests.popleft()
            
        # Add current request
        requests.append(current_time)
        
        # Check for flood
        if len(requests) > self.flood_threshold:
            self.block_ip(ip, "Flood detection", duration=self.block_duration)
            ids_logger.critical(f"FLOOD DETECTED: IP {ip} made {len(requests)} requests in {self.flood_window} seconds")
            return True
            
        return False
    
    def block_ip(self, ip: str, reason: str, duration: int = None, permanent: bool = False):
        """Block an IP address"""
        if permanent:
            self.permanent_blocks.add(ip)
            ids_logger.critical(f"IP {ip} permanently blocked: {reason}")
        else:
            block_duration = duration or self.block_duration
            self.blocked_ips[ip] = {
                'reason': reason,
                'blocked_at': time.time(),
                'expires': time.time() + block_duration,
                'duration': block_duration
            }
            ids_logger.warning(f"IP {ip} blocked for {block_duration}s: {reason}")
    
    def unblock_ip(self, ip: str):
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        if ip in self.permanent_blocks:
            self.permanent_blocks.remove(ip)
        ids_logger.info(f"IP {ip} manually unblocked")
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        current_time = time.time()
        blocked_list = []
        
        # Temporary blocks
        for ip, info in self.blocked_ips.items():
            if current_time < info['expires']:
                blocked_list.append({
                    'ip': ip,
                    'reason': info['reason'],
                    'blocked_at': datetime.fromtimestamp(info['blocked_at']).isoformat(),
                    'expires_at': datetime.fromtimestamp(info['expires']).isoformat(),
                    'type': 'temporary'
                })
        
        # Permanent blocks
        for ip in self.permanent_blocks:
            blocked_list.append({
                'ip': ip,
                'reason': 'Permanently blocked',
                'blocked_at': 'N/A',
                'expires_at': 'Never',
                'type': 'permanent'
            })
        
        return blocked_list


class IDSDatabase:
    """SQLite database for IDS events and analytics"""
    
    def __init__(self, db_path: str = "ids_security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize IDS database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    payload TEXT,
                    threat_details TEXT,
                    action_taken TEXT,
                    event_id TEXT UNIQUE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS request_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    user_agent TEXT,
                    payload_size INTEGER,
                    response_code INTEGER
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    blocked_at REAL NOT NULL,
                    expires_at REAL,
                    is_permanent BOOLEAN DEFAULT 0
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON request_metrics(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ip ON request_metrics(ip)")
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO security_events 
                (timestamp, event_type, severity, source_ip, user_agent, method, path, 
                 payload, threat_details, action_taken, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp, event.event_type, event.severity, event.source_ip,
                event.user_agent, event.method, event.path, event.payload,
                event.threat_details, event.action_taken, event.event_id
            ))
    
    def log_request_metrics(self, metrics: RequestMetrics):
        """Log request metrics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO request_metrics 
                (timestamp, ip, method, path, user_agent, payload_size, response_code)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                metrics.timestamp, metrics.ip, metrics.method, metrics.path,
                metrics.user_agent, metrics.payload_size, metrics.response_code
            ))
    
    def get_security_events(self, limit: int = 100, severity: str = None, 
                          since: datetime = None) -> List[Dict]:
        """Get security events with filters"""
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if since:
            query += " AND timestamp > ?"
            params.append(since.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_request_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """Get request analytics for the last N hours"""
        since_timestamp = time.time() - (hours * 3600)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Total requests
            total_requests = conn.execute(
                "SELECT COUNT(*) as count FROM request_metrics WHERE timestamp > ?",
                (since_timestamp,)
            ).fetchone()['count']
            
            # Requests by method
            method_stats = conn.execute("""
                SELECT method, COUNT(*) as count 
                FROM request_metrics 
                WHERE timestamp > ? 
                GROUP BY method
            """, (since_timestamp,)).fetchall()
            
            # Top IPs
            top_ips = conn.execute("""
                SELECT ip, COUNT(*) as count 
                FROM request_metrics 
                WHERE timestamp > ? 
                GROUP BY ip 
                ORDER BY count DESC 
                LIMIT 10
            """, (since_timestamp,)).fetchall()
            
            # Response codes
            response_codes = conn.execute("""
                SELECT response_code, COUNT(*) as count 
                FROM request_metrics 
                WHERE timestamp > ? 
                GROUP BY response_code
            """, (since_timestamp,)).fetchall()
            
            return {
                'total_requests': total_requests,
                'methods': [dict(row) for row in method_stats],
                'top_ips': [dict(row) for row in top_ips],
                'response_codes': [dict(row) for row in response_codes],
                'time_period_hours': hours
            }


class IDSManager:
    """Main IDS management class"""
    
    def __init__(self):
        self.threat_detector = ThreatDetector()
        self.ip_manager = IPBlockManager()
        self.database = IDSDatabase()
        
        # Configuration
        self.unauthorized_paths = [
            '/admin', '/config', '/system', '/internal',
            '/.env', '/backup', '/logs'
        ]
        
        self.sensitive_commands = [
            'exec', 'eval', 'system', 'shell',
            'import', 'require', 'include'
        ]
    
    def analyze_request(self, ip: str, method: str, path: str, 
                       user_agent: str, payload: str, extra_context: dict = None) -> Tuple[bool, List[SecurityEvent]]:
        """Comprehensive request analysis with optional extra context"""
        events = []
        should_block = False
        extra_context = extra_context or {}
        
        # Check if IP is already blocked (but allow trusted IPs)
        if not self._is_trusted_ip(ip):
            is_blocked, block_reason = self.ip_manager.is_ip_blocked(ip)
            if is_blocked:
                return True, []  # Already blocked, no need to analyze
        else:
            ids_logger.info(f"TRUSTED IP: {ip} bypassing block check")
        
        # Record request for flood detection (but not for trusted IPs)
        if not self._is_trusted_ip(ip):
            is_flood = self.ip_manager.record_request(ip)
            if is_flood:
                event = self._create_security_event(
                    "FLOOD_DETECTION", "CRITICAL", ip, user_agent, method, path,
                    payload, f"Flood detected: >{self.ip_manager.flood_threshold} requests/min",
                    "IP_BLOCKED"
                )
                events.append(event)
                should_block = True
        else:
            ids_logger.info(f"TRUSTED IP: {ip} bypassing flood detection")
        
        # Threat detection
        threats = self.threat_detector.analyze_payload(payload, user_agent)
        for threat_type, severity, details in threats:
            action = "LOGGED"
            if severity in ["HIGH", "CRITICAL"]:
                should_block = True
                action = "IP_BLOCKED"
                self.ip_manager.block_ip(ip, f"{threat_type}: {details}")
            
            event = self._create_security_event(
                threat_type, severity, ip, user_agent, method, path,
                payload, details, action
            )
            events.append(event)
        
        # Check for unauthorized access attempts
        if self._is_unauthorized_access(method, path, ip):
            event = self._create_security_event(
                "UNAUTHORIZED_ACCESS", "HIGH", ip, user_agent, method, path,
                payload, f"Unauthorized {method} access to {path}", "LOGGED"
            )
            events.append(event)
        
        # Log all events
        for event in events:
            self.database.log_security_event(event)
            ids_logger.warning(f"Security Event: {event.event_type} - {event.threat_details}")
        
        return should_block, events
    
    def log_request_metrics(self, ip: str, method: str, path: str, 
                          user_agent: str, payload_size: int, response_code: int):
        """Log request metrics for analytics"""
        metrics = RequestMetrics(
            ip=ip,
            method=method,
            path=path,
            timestamp=time.time(),
            user_agent=user_agent,
            payload_size=payload_size,
            response_code=response_code
        )
        self.database.log_request_metrics(metrics)
    
    def _create_security_event(self, event_type: str, severity: str, ip: str,
                             user_agent: str, method: str, path: str, payload: str,
                             details: str, action: str) -> SecurityEvent:
        """Create a security event"""
        event_id = hashlib.md5(
            f"{time.time()}{ip}{event_type}{details}".encode()
        ).hexdigest()
        
        return SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            severity=severity,
            source_ip=ip,
            user_agent=user_agent,
            method=method,
            path=path,
            payload=payload[:1000],  # Truncate long payloads
            threat_details=details,
            action_taken=action,
            event_id=event_id
        )
    
    def _is_unauthorized_access(self, method: str, path: str, ip: str = None) -> bool:
        """Check for unauthorized access patterns"""
        # Allow trusted IPs (localhost) to access admin paths
        if ip and self._is_trusted_ip(ip):
            # Trusted IPs can access admin paths
            if path.startswith('/admin'):
                ids_logger.info(f"TRUSTED ACCESS: {ip} allowed access to {path}")
                return False
        
        # Check unauthorized paths
        for unauthorized_path in self.unauthorized_paths:
            if unauthorized_path in path.lower():
                return True
        
        # Critical methods on sensitive endpoints (but allow trusted IPs)
        if method in ["PATCH", "DELETE", "PUT"] and "/api/devices/" in path:
            if ip and self._is_trusted_ip(ip):
                return False
            return True
            
        return False
    
    def _is_trusted_ip(self, ip: str) -> bool:
        """Check if IP is trusted (localhost/127.0.0.1)"""
        if not ip:
            return False
        
        trusted_ips = ["127.0.0.1", "::1", "localhost"]
        
        # Check exact match
        if ip in trusted_ips:
            return True
        
        # Check for localhost variations
        if ip.startswith("127.") or ip == "::1":
            return True
            
        return False
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        current_time = datetime.now()
        last_24h = current_time - timedelta(hours=24)
        
        return {
            'analytics': self.database.get_request_analytics(24),
            'recent_events': self.database.get_security_events(50),
            'critical_events': self.database.get_security_events(20, severity="CRITICAL"),
            'blocked_ips': self.ip_manager.get_blocked_ips(),
            'system_status': {
                'ids_active': True,
                'flood_threshold': self.ip_manager.flood_threshold,
                'block_duration': self.ip_manager.block_duration,
                'total_blocked_ips': len(self.ip_manager.blocked_ips) + len(self.ip_manager.permanent_blocks)
            }
        }


# Global IDS instance
ids_manager = IDSManager()