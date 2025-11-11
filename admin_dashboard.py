"""
Admin Dashboard Backend for IDS Management
Provides comprehensive security monitoring and management capabilities
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import time
import sqlite3
from ids_system import ids_manager
from ids_middleware import get_blocked_ips, get_security_stats, block_ip_manually, unblock_ip_manually

# Create admin router
admin_router = APIRouter(prefix="/admin", tags=["Admin Dashboard"])

# Data models for admin endpoints
class IPBlockRequest(BaseModel):
    ip: str
    reason: str
    permanent: bool = False

class IPUnblockRequest(BaseModel):
    ip: str

class SecurityEventFilter(BaseModel):
    severity: Optional[str] = None
    event_type: Optional[str] = None
    hours: int = 24
    limit: int = 100

class AnalyticsRequest(BaseModel):
    hours: int = 24
    group_by: str = "hour"  # hour, day, method, ip

# Admin Dashboard HTML
ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Admin Dashboard - Medical IoT Security</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        color: #333;
        position: relative;
        overflow-x: hidden;
    }
    
    body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
            radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.3) 0%, transparent 50%),
            radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.2) 0%, transparent 50%);
        pointer-events: none;
        z-index: -1;
        animation: backgroundFloat 20s ease-in-out infinite;
    }
    
    @keyframes backgroundFloat {
        0%, 100% { transform: translate(0, 0) scale(1); }
        33% { transform: translate(30px, -30px) scale(1.1); }
        66% { transform: translate(-20px, 20px) scale(0.9); }
    }        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        
        .header .status {
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #27ae60;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, #667eea, #764ba2, #f093fb);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 16px 48px rgba(0, 0, 0, 0.15), 0 0 20px rgba(102, 126, 234, 0.3);
        }
        
        .card:hover::before {
            transform: scaleX(1);
        }
        
        .card h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        
        .metric-value {
            font-weight: bold;
            font-size: 1.2em;
        }
        
        .metric-value.critical { color: #e74c3c; }
        .metric-value.warning { color: #f39c12; }
        .metric-value.success { color: #27ae60; }
        .metric-value.info { color: #3498db; }
        
        .chart-container {
            grid-column: span 2;
            height: 400px;
        }
        
        .table-container {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        th {
            background: #f8f9fa;
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        
        .severity-critical { background: #ffebee; color: #c62828; }
        .severity-high { background: #fff3e0; color: #ef6c00; }
        .severity-medium { background: #f3e5f5; color: #7b1fa2; }
        .severity-low { background: #e8f5e8; color: #2e7d32; }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .btn-success {
            background: #27ae60;
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        
        .refresh-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: #3498db;
            color: white;
            border: none;
            font-size: 20px;
            cursor: pointer;
            box-shadow: 0 4px 16px rgba(52, 152, 219, 0.3);
            transition: all 0.3s ease;
        }
        
        .refresh-btn:hover {
            transform: scale(1.1);
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        
        .alert-danger {
            background: #ffebee;
            color: #c62828;
            border-left: 4px solid #c62828;
        }
        
        .alert-warning {
            background: #fff3e0;
            color: #ef6c00;
            border-left: 4px solid #ef6c00;
        }
        
        .ip-input {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        
        .ip-input input {
            flex: 1;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <h1>🛡️ IDS Admin Dashboard</h1>
            <p>Medical IoT Security Monitoring & Management</p>
            <div class="status">
                <div class="status-item">
                    <div class="status-indicator"></div>
                    <span>IDS Active</span>
                </div>
                <div class="status-item">
                    <strong>Last Updated:</strong> <span id="lastUpdate">Loading...</span>
                </div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <!-- System Overview -->
            <div class="card">
                <h3>🎯 System Overview</h3>
                <div id="systemOverview" class="loading">Loading...</div>
            </div>
            
            <!-- Request Analytics -->
            <div class="card">
                <h3>📊 Request Analytics (24h)</h3>
                <div id="requestAnalytics" class="loading">Loading...</div>
            </div>
            
            <!-- Security Alerts -->
            <div class="card">
                <h3>🚨 Recent Security Events</h3>
                <div id="securityEvents" class="loading">Loading...</div>
            </div>
            
            <!-- Blocked IPs -->
            <div class="card">
                <h3>🚫 Blocked IPs</h3>
                <div id="blockedIPs" class="loading">Loading...</div>
                <div class="ip-input">
                    <input type="text" id="blockIP" placeholder="IP to block">
                    <input type="text" id="blockReason" placeholder="Reason">
                    <button class="btn btn-danger" onclick="blockIP()">Block IP</button>
                </div>
            </div>
            
            <!-- Request Volume Chart -->
            <div class="card chart-container">
                <h3>📈 Request Volume Analysis</h3>
                <div id="requestChart" class="loading">Loading...</div>
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshDashboard()">🔄</button>
    
    <script>
        let refreshInterval;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            refreshDashboard();
            refreshInterval = setInterval(refreshDashboard, 30000); // Refresh every 30 seconds
        });
        
        async function refreshDashboard() {
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
            
            // Show loading states
            const loadingElements = document.querySelectorAll('.loading');
            loadingElements.forEach(el => el.style.display = 'block');
            
            try {
                // Load all data in parallel for better performance
                const [systemData, analyticsData, eventsData, blockedData, threatData] = await Promise.all([
                    fetch('/admin/ids/overview').then(r => r.json()),
                    fetch('/admin/ids/analytics').then(r => r.json()),
                    fetch('/admin/ids/events?limit=20').then(r => r.json()),
                    fetch('/admin/ids/blocked-ips').then(r => r.json()),
                    fetch('/admin/ids/top-threats').then(r => r.json()).catch(() => null)
                ]);
                
                // Render all components
                renderSystemOverview(systemData);
                renderRequestAnalytics(analyticsData);
                renderSecurityEvents(eventsData);
                renderBlockedIPs(blockedData);
                if (threatData) renderThreatAnalysis(threatData);
                
                // Hide loading states
                loadingElements.forEach(el => el.style.display = 'none');
                
                // Show success indicator
                showNotification('Dashboard updated successfully', 'success');
                
            } catch (error) {
                console.error('Dashboard refresh error:', error);
                showNotification('Failed to refresh dashboard: ' + error.message, 'error');
                loadingElements.forEach(el => el.style.display = 'none');
            }
        }
        
        function renderSystemOverview(data) {
            const html = `
                <div class="metric">
                    <span>Total Requests (24h)</span>
                    <span class="metric-value info">${data.analytics.total_requests.toLocaleString()}</span>
                </div>
                <div class="metric">
                    <span>Security Events</span>
                    <span class="metric-value warning">${data.recent_events.length}</span>
                </div>
                <div class="metric">
                    <span>Critical Alerts</span>
                    <span class="metric-value critical">${data.critical_events.length}</span>
                </div>
                <div class="metric">
                    <span>Blocked IPs</span>
                    <span class="metric-value critical">${data.blocked_ips.length}</span>
                </div>
                <div class="metric">
                    <span>Flood Threshold</span>
                    <span class="metric-value info">${data.system_status.flood_threshold}/min</span>
                </div>
            `;
            document.getElementById('systemOverview').innerHTML = html;
        }
        
        function renderRequestAnalytics(data) {
            let html = '<div class="table-container"><table><tr><th>Method</th><th>Count</th></tr>';
            data.methods.forEach(method => {
                html += `<tr><td>${method.method}</td><td>${method.count}</td></tr>`;
            });
            html += '</table></div>';
            document.getElementById('requestAnalytics').innerHTML = html;
        }
        
        function renderSecurityEvents(events) {
            if (events.length === 0) {
                document.getElementById('securityEvents').innerHTML = '<p>No recent security events</p>';
                return;
            }
            
            let html = '<div class="table-container"><table><tr><th>Time</th><th>Type</th><th>Severity</th><th>IP</th></tr>';
            events.forEach(event => {
                const time = new Date(event.timestamp).toLocaleTimeString();
                html += `<tr class="severity-${event.severity.toLowerCase()}">
                    <td>${time}</td>
                    <td>${event.event_type}</td>
                    <td>${event.severity}</td>
                    <td>${event.source_ip}</td>
                </tr>`;
            });
            html += '</table></div>';
            document.getElementById('securityEvents').innerHTML = html;
        }
        
        function renderBlockedIPs(blockedIPs) {
            if (blockedIPs.length === 0) {
                document.getElementById('blockedIPs').innerHTML += '<p>No blocked IPs</p>';
                return;
            }
            
            let html = '<div class="table-container"><table><tr><th>IP</th><th>Reason</th><th>Type</th><th>Action</th></tr>';
            blockedIPs.forEach(ip => {
                html += `<tr>
                    <td>${ip.ip}</td>
                    <td>${ip.reason}</td>
                    <td>${ip.type}</td>
                    <td>
                        ${ip.type === 'temporary' ? 
                          `<button class="btn btn-success" onclick="unblockIP('${ip.ip}')">Unblock</button>` : 
                          'Permanent'
                        }
                    </td>
                </tr>`;
            });
            html += '</table></div>';
            document.getElementById('blockedIPs').innerHTML = html.replace('<div class="loading">Loading...</div>', '');
        }
        
        async function blockIP() {
            const ip = document.getElementById('blockIP').value;
            const reason = document.getElementById('blockReason').value;
            
            if (!ip || !reason) {
                alert('Please provide both IP and reason');
                return;
            }
            
            try {
                const response = await fetch('/admin/ids/block-ip', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip, reason, permanent: false})
                });
                
                if (response.ok) {
                    document.getElementById('blockIP').value = '';
                    document.getElementById('blockReason').value = '';
                    refreshDashboard();
                } else {
                    alert('Failed to block IP');
                }
            } catch (error) {
                alert('Error blocking IP: ' + error.message);
            }
        }
        
        async function unblockIP(ip) {
            if (!confirm(`Are you sure you want to unblock IP ${ip}?`)) {
                return;
            }
            
            try {
                showNotification(`Unblocking IP ${ip}...`, 'info');
                
                const response = await fetch('/admin/ids/unblock-ip', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip})
                });
                
                if (response.ok) {
                    showNotification(`Successfully unblocked IP ${ip}`, 'success');
                    refreshDashboard();
                } else {
                    const error = await response.json();
                    showNotification('Failed to unblock IP: ' + (error.detail || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error unblocking IP: ' + error.message, 'error');
            }
        }
        
        // Enhanced notification system
        function showNotification(message, type = 'info', duration = 5000) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas ${getNotificationIcon(type)}"></i>
                    <span>${message}</span>
                    <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
                </div>
            `;
            
            const container = document.getElementById('notification-container') || createNotificationContainer();
            container.appendChild(notification);
            
            // Auto-remove after duration
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.style.opacity = '0';
                    setTimeout(() => notification.remove(), 300);
                }
            }, duration);
        }
        
        function getNotificationIcon(type) {
            const icons = {
                success: 'fa-check-circle',
                error: 'fa-exclamation-circle',
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };
            return icons[type] || icons.info;
        }
        
        function createNotificationContainer() {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 10px;
                max-width: 400px;
            `;
            document.body.appendChild(container);
            return container;
        }
        
        // Enhanced rendering functions
        function renderThreatAnalysis(data) {
            if (!data || !data.top_threats) return;
            
            const container = document.getElementById('threatAnalysis');
            if (!container) return;
            
            let html = '<h4>Top Threats (24h)</h4>';
            html += '<div class="threat-list">';
            
            data.top_threats.slice(0, 5).forEach(threat => {
                const severity = getThreatSeverity(threat.type);
                html += `
                    <div class="threat-item severity-${severity}">
                        <span class="threat-type">${threat.type}</span>
                        <span class="threat-count">${threat.count}</span>
                    </div>
                `;
            });
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        function getThreatSeverity(threatType) {
            const severityMap = {
                'Code Injection': 'critical',
                'Command Injection': 'critical',
                'SQLi': 'high',
                'XSS': 'medium',
                'Suspicious User Agent': 'low'
            };
            return severityMap[threatType] || 'medium';
        }
        
        // Real-time updates with WebSocket simulation
        function startRealTimeUpdates() {
            // Simulate real-time updates with more frequent refreshes
            setInterval(() => {
                refreshDashboard();
            }, 10000); // Update every 10 seconds
            
            // Add visual indicator for live updates
            const indicator = document.createElement('div');
            indicator.className = 'live-indicator';
            indicator.innerHTML = '<i class="fas fa-circle"></i> LIVE';
            indicator.style.cssText = `
                position: fixed;
                top: 10px;
                left: 50%;
                transform: translateX(-50%);
                background: #27ae60;
                color: white;
                padding: 5px 15px;
                border-radius: 15px;
                font-size: 12px;
                font-weight: bold;
                z-index: 1000;
                animation: pulse 2s infinite;
            `;
            document.body.appendChild(indicator);
        }
        
        // Initialize enhanced features
        document.addEventListener('DOMContentLoaded', function() {
            refreshDashboard();
            refreshInterval = setInterval(refreshDashboard, 30000);
            startRealTimeUpdates();
        });
    </script>
</body>
</html>
"""

@admin_router.get("/", response_class=HTMLResponse)
async def admin_dashboard():
    """Serve the main admin dashboard"""
    return HTMLResponse(content=ADMIN_DASHBOARD_HTML)

@admin_router.get("/ids/overview")
async def get_ids_overview():
    """Get comprehensive IDS overview data"""
    try:
        dashboard_data = ids_manager.get_dashboard_data()
        return JSONResponse(content=dashboard_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get overview: {str(e)}")

@admin_router.get("/ids/analytics")
async def get_request_analytics(hours: int = Query(24, ge=1, le=168)):
    """Get request analytics for specified time period"""
    try:
        analytics = ids_manager.database.get_request_analytics(hours)
        return JSONResponse(content=analytics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analytics: {str(e)}")

@admin_router.get("/ids/events")
async def get_security_events(
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    hours: int = Query(24, ge=1, le=168)
):
    """Get security events with filtering"""
    try:
        since = datetime.now() - timedelta(hours=hours) if hours else None
        events = ids_manager.database.get_security_events(limit, severity, since)
        return JSONResponse(content=events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get events: {str(e)}")

@admin_router.get("/ids/blocked-ips")
async def get_blocked_ips_endpoint():
    """Get list of blocked IPs"""
    try:
        blocked_ips = get_blocked_ips()
        return JSONResponse(content=blocked_ips)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get blocked IPs: {str(e)}")

@admin_router.post("/ids/block-ip")
async def block_ip_endpoint(request: IPBlockRequest):
    """Manually block an IP address"""
    try:
        block_ip_manually(request.ip, request.reason, request.permanent)
        return JSONResponse(content={
            "success": True,
            "message": f"IP {request.ip} has been blocked",
            "permanent": request.permanent
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to block IP: {str(e)}")

@admin_router.post("/ids/unblock-ip")
async def unblock_ip_endpoint(request: IPUnblockRequest):
    """Manually unblock an IP address"""
    try:
        unblock_ip_manually(request.ip)
        return JSONResponse(content={
            "success": True,
            "message": f"IP {request.ip} has been unblocked"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unblock IP: {str(e)}")

@admin_router.get("/ids/stats")
async def get_security_stats_endpoint():
    """Get current security statistics"""
    try:
        stats = get_security_stats()
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@admin_router.get("/ids/top-threats")
async def get_top_threats(hours: int = Query(24, ge=1, le=168)):
    """Get top threat types and IPs"""
    try:
        since = datetime.now() - timedelta(hours=hours)
        events = ids_manager.database.get_security_events(1000, since=since)
        
        # Analyze threat types
        threat_counts = {}
        ip_counts = {}
        
        for event in events:
            threat_type = event['event_type']
            ip = event['source_ip']
            
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Sort by count
        top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return JSONResponse(content={
            "top_threats": [{"type": t[0], "count": t[1]} for t in top_threats],
            "top_attacking_ips": [{"ip": ip[0], "count": ip[1]} for ip in top_ips],
            "time_period_hours": hours
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get top threats: {str(e)}")

@admin_router.delete("/ids/events")
async def clear_old_events(days: int = Query(30, ge=1, le=365)):
    """Clear security events older than specified days"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(ids_manager.database.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM security_events WHERE timestamp < ?",
                (cutoff_date.isoformat(),)
            )
            deleted_count = cursor.rowcount
        
        return JSONResponse(content={
            "success": True,
            "message": f"Deleted {deleted_count} events older than {days} days"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear events: {str(e)}")

@admin_router.get("/ids/health")
async def ids_health_check():
    """IDS system health check"""
    try:
        return JSONResponse(content={
            "status": "healthy",
            "ids_active": True,
            "database_accessible": True,
            "blocked_ips_count": len(get_blocked_ips()),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )