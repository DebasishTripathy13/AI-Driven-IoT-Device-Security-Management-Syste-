/**
 * Nozomi Industrial Security Platform JavaScript
 * Professional IoT Security Dashboard
 */

class NozomiSecurityPlatform {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8001';
        this.refreshInterval = 30000; // 30 seconds
        this.charts = {};
        this.refreshTimer = null;
        
        this.init();
    }

    async init() {
        console.log('🛡️ Initializing Nozomi Security Platform...');
        
        // Show loading overlay initially
        this.showLoading();
        
        // Initialize components
        await this.loadInitialData();
        await this.initializeCharts();
        this.setupEventListeners();
        this.startPeriodicRefresh();
        
        // Hide loading overlay
        this.hideLoading();
        
        console.log('✅ Nozomi Security Platform initialized successfully');
    }

    // Loading Management
    showLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.add('show');
        }
    }

    hideLoading() {
        setTimeout(() => {
            const overlay = document.getElementById('loading-overlay');
            if (overlay) {
                overlay.classList.remove('show');
            }
        }, 1000);
    }

    // Data Loading
    async loadInitialData() {
        try {
            await Promise.all([
                this.updateMetrics(),
                this.loadSecurityThreats(),
                this.loadDeviceStatus(),
                this.loadActivityTimeline(),
                this.updateSystemHealth()
            ]);
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.handleError('Failed to load dashboard data');
        }
    }

    // API Communication
    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.apiBaseUrl}${endpoint}`, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            
            if (!response.ok) {
                throw new Error(`API call failed: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`API call error for ${endpoint}:`, error);
            return null;
        }
    }

    // Metrics Updates
    async updateMetrics() {
        try {
            const [securityData, deviceData, trafficData] = await Promise.all([
                this.apiCall('/admin/ai-security/metrics?hours=24'),
                this.apiCall('/api/devices'),
                this.apiCall('/api/status')
            ]);

            if (securityData) {
                this.updateMetricCard('critical-alerts', securityData.request_processing?.blocked || 2);
                this.updateMetricCard('security-score', 
                    Math.round((1 - (securityData.request_processing?.block_rate_percent || 0) / 100) * 100));
            }

            if (deviceData) {
                this.updateMetricCard('active-devices', deviceData.length || 10);
                document.getElementById('asset-count').textContent = deviceData.length || 10;
            }

            // Simulate traffic volume
            this.updateMetricCard('traffic-volume', '2.4');

        } catch (error) {
            console.error('Error updating metrics:', error);
        }
    }

    updateMetricCard(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    // Security Threats
    async loadSecurityThreats() {
        const threatList = document.getElementById('threat-list');
        if (!threatList) return;

        try {
            const securityData = await this.apiCall('/admin/ai-security/recent-decisions?limit=10');
            
            // Mock threats for demonstration
            const mockThreats = [
                {
                    id: 1,
                    severity: 'critical',
                    title: 'Suspicious Network Activity Detected',
                    description: 'Unusual traffic patterns from medical device med-ecg-001',
                    timestamp: new Date(Date.now() - 300000).toISOString(),
                    source: '192.168.1.105'
                },
                {
                    id: 2,
                    severity: 'high',
                    title: 'Unauthorized Access Attempt',
                    description: 'Multiple failed authentication attempts detected',
                    timestamp: new Date(Date.now() - 900000).toISOString(),
                    source: '203.0.113.45'
                },
                {
                    id: 3,
                    severity: 'medium',
                    title: 'Firmware Version Mismatch',
                    description: 'Device running outdated firmware version',
                    timestamp: new Date(Date.now() - 1800000).toISOString(),
                    source: 'med-pump-002'
                }
            ];

            threatList.innerHTML = mockThreats.map(threat => this.createThreatItem(threat)).join('');
            
            // Update threat count in sidebar
            document.getElementById('threat-count').textContent = mockThreats.filter(t => 
                t.severity === 'critical' || t.severity === 'high').length;

        } catch (error) {
            console.error('Error loading threats:', error);
            threatList.innerHTML = '<div class="threat-item">Unable to load security threats</div>';
        }
    }

    createThreatItem(threat) {
        const timeAgo = this.formatTimeAgo(new Date(threat.timestamp));
        return `
            <div class="threat-item">
                <div class="threat-severity ${threat.severity}"></div>
                <div class="threat-info">
                    <div class="threat-title">${threat.title}</div>
                    <div class="threat-description">${threat.description}</div>
                    <div class="threat-meta">Source: ${threat.source} • ${timeAgo}</div>
                </div>
            </div>
        `;
    }

    // Device Status
    async loadDeviceStatus() {
        const deviceGrid = document.getElementById('device-grid');
        if (!deviceGrid) return;

        try {
            const devices = await this.apiCall('/api/devices');
            
            if (devices && devices.length > 0) {
                deviceGrid.innerHTML = devices.slice(0, 6).map(device => this.createDeviceCard(device)).join('');
            } else {
                // Mock devices for demonstration
                const mockDevices = [
                    { deviceId: 'med-ecg-001', deviceType: 'ECG Monitor', status: 'online', lastSeen: new Date() },
                    { deviceId: 'med-pump-002', deviceType: 'Infusion Pump', status: 'online', lastSeen: new Date() },
                    { deviceId: 'med-monitor-003', deviceType: 'Patient Monitor', status: 'warning', lastSeen: new Date() },
                    { deviceId: 'med-ventilator-004', deviceType: 'Ventilator', status: 'online', lastSeen: new Date() },
                    { deviceId: 'med-defib-005', deviceType: 'Defibrillator', status: 'offline', lastSeen: new Date(Date.now() - 3600000) },
                    { deviceId: 'med-ultrasound-006', deviceType: 'Ultrasound', status: 'online', lastSeen: new Date() }
                ];
                
                deviceGrid.innerHTML = mockDevices.map(device => this.createDeviceCard(device)).join('');
            }
        } catch (error) {
            console.error('Error loading device status:', error);
            deviceGrid.innerHTML = '<div class="device-card">Unable to load device status</div>';
        }
    }

    createDeviceCard(device) {
        const statusClass = device.status === 'online' ? 'online' : 
                          device.status === 'warning' ? 'warning' : 'offline';
        const lastSeen = this.formatTimeAgo(new Date(device.lastSeen));
        
        return `
            <div class="device-card">
                <div class="device-header">
                    <div class="device-name">${device.deviceId}</div>
                    <div class="device-status ${statusClass}"></div>
                </div>
                <div class="device-type">${device.deviceType}</div>
                <div class="device-metrics">
                    <span>Status: ${device.status}</span>
                    <span>Last seen: ${lastSeen}</span>
                </div>
            </div>
        `;
    }

    // Activity Timeline
    async loadActivityTimeline() {
        const timeline = document.getElementById('activity-timeline');
        if (!timeline) return;

        try {
            // Mock recent activities
            const activities = [
                {
                    id: 1,
                    type: 'security',
                    icon: 'fas fa-shield-alt',
                    title: 'Security scan completed',
                    description: 'All devices scanned for vulnerabilities',
                    timestamp: new Date(Date.now() - 300000)
                },
                {
                    id: 2,
                    type: 'device',
                    icon: 'fas fa-microchip',
                    title: 'New device registered',
                    description: 'med-ecg-007 added to network',
                    timestamp: new Date(Date.now() - 600000)
                },
                {
                    id: 3,
                    type: 'alert',
                    icon: 'fas fa-exclamation-triangle',
                    title: 'Anomaly detected',
                    description: 'Unusual traffic pattern from device med-pump-002',
                    timestamp: new Date(Date.now() - 1200000)
                },
                {
                    id: 4,
                    type: 'update',
                    icon: 'fas fa-download',
                    title: 'Firmware update applied',
                    description: 'med-ventilator-004 updated to version 2.1.0',
                    timestamp: new Date(Date.now() - 1800000)
                },
                {
                    id: 5,
                    type: 'maintenance',
                    icon: 'fas fa-wrench',
                    title: 'Scheduled maintenance',
                    description: 'System backup completed successfully',
                    timestamp: new Date(Date.now() - 3600000)
                }
            ];

            timeline.innerHTML = activities.map(activity => this.createActivityItem(activity)).join('');
            
        } catch (error) {
            console.error('Error loading activity timeline:', error);
            timeline.innerHTML = '<div class="activity-item">Unable to load recent activities</div>';
        }
    }

    createActivityItem(activity) {
        const timeAgo = this.formatTimeAgo(activity.timestamp);
        return `
            <div class="activity-item">
                <div class="activity-icon">
                    <i class="${activity.icon}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${activity.title}</div>
                    <div class="activity-description">${activity.description}</div>
                    <div class="activity-time">${timeAgo}</div>
                </div>
            </div>
        `;
    }

    // System Health
    async updateSystemHealth() {
        try {
            // Simulate system health metrics
            const healthMetrics = [
                { label: 'CPU Usage', value: Math.floor(Math.random() * 30) + 20 },
                { label: 'Memory Usage', value: Math.floor(Math.random() * 20) + 50 },
                { label: 'Network Load', value: Math.floor(Math.random() * 15) + 10 },
                { label: 'Storage', value: Math.floor(Math.random() * 10) + 80 }
            ];

            const healthItems = document.querySelectorAll('.health-item');
            healthItems.forEach((item, index) => {
                if (healthMetrics[index]) {
                    const progress = item.querySelector('.health-progress');
                    const value = item.querySelector('.health-value');
                    if (progress && value) {
                        progress.style.width = `${healthMetrics[index].value}%`;
                        value.textContent = `${healthMetrics[index].value}%`;
                    }
                }
            });
        } catch (error) {
            console.error('Error updating system health:', error);
        }
    }

    // Chart Initialization
    async initializeCharts() {
        // Placeholder for chart initialization
        // In a real implementation, you would use Chart.js, D3.js, or similar
        console.log('📊 Initializing charts...');
    }

    // Event Listeners
    setupEventListeners() {
        // Navigation items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleNavigation(item);
            });
        });

        // Time range selector
        document.querySelectorAll('.time-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.updateAnalyticsChart(btn.textContent);
            });
        });

        // Refresh buttons
        document.querySelectorAll('.btn-refresh, .btn-icon').forEach(btn => {
            btn.addEventListener('click', () => {
                this.handleRefresh(btn);
            });
        });
    }

    handleNavigation(navItem) {
        // Remove active class from all nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        
        // Add active class to clicked item
        navItem.classList.add('active');
        
        // Update page title
        const pageTitle = navItem.querySelector('span').textContent;
        document.querySelector('.page-title').textContent = pageTitle;
        
        console.log(`Navigating to: ${pageTitle}`);
    }

    handleRefresh(button) {
        // Add loading animation
        const icon = button.querySelector('i');
        if (icon) {
            icon.classList.add('fa-spin');
            setTimeout(() => {
                icon.classList.remove('fa-spin');
            }, 1000);
        }
        
        // Refresh data
        this.refreshDashboardData();
    }

    // Periodic Refresh
    startPeriodicRefresh() {
        this.refreshTimer = setInterval(() => {
            this.refreshDashboardData();
        }, this.refreshInterval);
    }

    async refreshDashboardData() {
        console.log('🔄 Refreshing dashboard data...');
        
        try {
            await Promise.all([
                this.updateMetrics(),
                this.loadSecurityThreats(),
                this.loadDeviceStatus(),
                this.updateSystemHealth()
            ]);
            
            // Update last updated time
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', { 
                hour12: false,
                hour: '2-digit',
                minute: '2-digit'
            });
            document.getElementById('last-update-time').textContent = timeString;
            
        } catch (error) {
            console.error('Error refreshing dashboard:', error);
        }
    }

    // Utility Functions
    formatTimeAgo(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return `${diffDays}d ago`;
    }

    handleError(message) {
        console.error('Platform Error:', message);
        // In a real implementation, show a toast notification or error modal
    }

    // Public API Methods
    updateAnalyticsChart(timeRange) {
        console.log(`📈 Updating analytics chart for ${timeRange}`);
        // Implement chart update logic
    }

    expandTopology() {
        console.log('🔍 Expanding network topology view');
        // Implement topology expansion
    }

    refreshAllData() {
        this.refreshDashboardData();
    }

    destroy() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
    }
}

// Global Functions for HTML onclick handlers
function refreshDashboard() {
    if (window.nozomiPlatform) {
        window.nozomiPlatform.refreshAllData();
    }
}

function expandTopology() {
    if (window.nozomiPlatform) {
        window.nozomiPlatform.expandTopology();
    }
}

function refreshThreats() {
    if (window.nozomiPlatform) {
        window.nozomiPlatform.loadSecurityThreats();
    }
}

function viewAllActivities() {
    console.log('📋 Opening full activity log');
    // Implement full activity view
}

// Initialize the platform when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.nozomiPlatform = new NozomiSecurityPlatform();
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (window.nozomiPlatform) {
        window.nozomiPlatform.destroy();
    }
});

console.log('🛡️ Nozomi Security Platform JavaScript loaded');