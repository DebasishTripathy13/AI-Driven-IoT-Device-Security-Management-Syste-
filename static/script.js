// Medical IoT Device Manager - Frontend JavaScript

class DeviceManager {
    constructor() {
        this.devices = [];
        this.selectedDevices = new Set();
        this.continuousActive = false;
        this.init();
    }

    async init() {
        await this.loadDevices();
        this.setupEventListeners();
        this.updateStats();
    }

    // API Communication
    async apiCall(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        try {
            showLoading(true);
            const response = await fetch(`/api${endpoint}`, {
                ...defaultOptions,
                ...options,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || `HTTP ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            showToast(`Error: ${error.message}`, 'error');
            throw error;
        } finally {
            showLoading(false);
        }
    }

    // Device Management
    async loadDevices() {
        try {
            this.devices = await this.apiCall('/devices');
            this.renderDevices();
            this.populateDeviceTypeFilter();
            this.updateStats();
            logActivity('Devices loaded successfully', 'info');
        } catch (error) {
            logActivity('Failed to load devices', 'error');
        }
    }

    renderDevices() {
        const grid = document.getElementById('device-grid');
        if (!grid) return;

        if (this.devices.length === 0) {
            grid.innerHTML = `
                <div class="no-devices">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>No devices found. Please register devices first.</p>
                </div>
            `;
            return;
        }

        grid.innerHTML = this.devices.map(device => this.createDeviceCard(device)).join('');
    }

    createDeviceCard(device) {
        const isConnected = device.status === 'Connected';
        const deviceIcon = this.getDeviceIcon(device.deviceType);
        
        return `
            <div class="device-card ${isConnected ? 'connected' : 'disconnected'}" 
                 data-device-id="${device.deviceId}" 
                 data-device-type="${device.deviceType}">
                <div class="device-header">
                    <div>
                        <div class="device-title">
                            <i class="${deviceIcon}"></i>
                            ${device.deviceType}
                        </div>
                        <div class="device-id">${device.deviceId}</div>
                    </div>
                    <div class="device-status ${isConnected ? 'connected' : 'disconnected'}">
                        <i class="fas fa-circle"></i>
                        ${device.status}
                    </div>
                </div>
                
                <div class="device-info">
                    <div class="device-info-item">
                        <span class="device-info-label">Manufacturer:</span>
                        <span>${device.manufacturer}</span>
                    </div>
                    <div class="device-info-item">
                        <span class="device-info-label">OS:</span>
                        <span>${device.osName} ${device.osVersion}</span>
                    </div>
                </div>
                
                <div class="device-actions">
                    <div class="action-row">
                        <button class="btn btn-primary btn-sm" onclick="deviceManager.sendQuickMessage('${device.deviceId}', 'normal')">
                            <i class="fas fa-paper-plane"></i> Telemetry
                        </button>
                        <button class="btn btn-info btn-sm" onclick="deviceManager.sendQuickMessage('${device.deviceId}', 'status')">
                            <i class="fas fa-check-circle"></i> Status
                        </button>
                        <button class="btn ${isConnected ? 'btn-danger' : 'btn-success'} btn-sm" 
                                onclick="deviceManager.toggleDeviceConnection('${device.deviceId}')">
                            <i class="fas fa-${isConnected ? 'unlink' : 'link'}"></i>
                            ${isConnected ? 'Disconnect' : 'Connect'}
                        </button>
                    </div>
                    <div class="action-row">
                        <button class="btn btn-warning btn-sm" onclick="openCodeModal('${device.deviceId}')">
                            <i class="fas fa-code"></i> Send Code
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="openPatchModal('${device.deviceId}')">
                            <i class="fas fa-band-aid"></i> Send Patch
                        </button>
                        <button class="btn btn-dark btn-sm" onclick="deviceManager.openDeviceModal('${device.deviceId}')">
                            <i class="fas fa-cogs"></i> Advanced
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    getDeviceIcon(deviceType) {
        const icons = {
            'ECG': 'fas fa-heartbeat',
            'PulseOximeter': 'fas fa-hand-holding-heart',
            'BloodPressureMonitor': 'fas fa-thermometer-half',
            'InfusionPump': 'fas fa-syringe',
            'Ventilator': 'fas fa-lungs',
            'Glucometer': 'fas fa-tint',
            'Thermometer': 'fas fa-thermometer-three-quarters',
            'Defibrillator': 'fas fa-bolt',
            'EEG': 'fas fa-brain',
            'Ultrasound': 'fas fa-wave-square'
        };
        return icons[deviceType] || 'fas fa-medical-kit';
    }

    populateDeviceTypeFilter() {
        const filter = document.getElementById('device-filter');
        if (!filter) return;

        const deviceTypes = [...new Set(this.devices.map(d => d.deviceType))];
        const currentValue = filter.value;
        
        filter.innerHTML = '<option value="">All Device Types</option>' +
            deviceTypes.map(type => `<option value="${type}">${type}</option>`).join('');
        
        filter.value = currentValue;
    }

    filterDevices() {
        const filter = document.getElementById('device-filter');
        const filterValue = filter ? filter.value : '';
        const cards = document.querySelectorAll('.device-card');

        cards.forEach(card => {
            const deviceType = card.dataset.deviceType;
            card.style.display = (!filterValue || deviceType === filterValue) ? 'block' : 'none';
        });
    }

    toggleDeviceSelection(deviceId) {
        if (this.selectedDevices.has(deviceId)) {
            this.selectedDevices.delete(deviceId);
        } else {
            this.selectedDevices.add(deviceId);
        }
    }

    getSelectedDevices() {
        const checkboxes = document.querySelectorAll('.device-select input:checked');
        return Array.from(checkboxes).map(cb => 
            cb.closest('.device-card').dataset.deviceId
        );
    }

    updateStats() {
        const connectedCount = this.devices.filter(d => d.status === 'Connected').length;
        const totalCount = this.devices.length;

        const connectedEl = document.getElementById('connected-count');
        const totalEl = document.getElementById('total-count');

        if (connectedEl) connectedEl.textContent = connectedCount;
        if (totalEl) totalEl.textContent = totalCount;
    }

    // Device Actions
    async toggleDeviceConnection(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) return;

        const isConnected = device.status === 'Connected';
        const action = isConnected ? 'disconnect' : 'connect';

        try {
            await this.apiCall(`/devices/${action}`, {
                method: 'POST',
                body: JSON.stringify({ deviceIds: [deviceId] })
            });

            logActivity(`${isConnected ? 'Disconnected' : 'Connected'} device ${deviceId}`, 'success');
            await this.loadDevices(); // Refresh device list
        } catch (error) {
            logActivity(`Failed to ${action} device ${deviceId}`, 'error');
        }
    }

    async connectAllDevices() {
        try {
            const deviceIds = this.devices.map(d => d.deviceId);
            const result = await this.apiCall('/devices/connect', {
                method: 'POST',
                body: JSON.stringify({ deviceIds })
            });

            showToast(result.message, 'success');
            logActivity('Connected all devices', 'success');
            await this.loadDevices();
        } catch (error) {
            logActivity('Failed to connect all devices', 'error');
        }
    }

    async disconnectAllDevices() {
        try {
            const connectedDevices = this.devices
                .filter(d => d.status === 'Connected')
                .map(d => d.deviceId);

            if (connectedDevices.length === 0) {
                showToast('No devices to disconnect', 'warning');
                return;
            }

            const result = await this.apiCall('/devices/disconnect', {
                method: 'POST',
                body: JSON.stringify({ deviceIds: connectedDevices })
            });

            showToast(result.message, 'success');
            logActivity('Disconnected all devices', 'success');
            await this.loadDevices();
        } catch (error) {
            logActivity('Failed to disconnect all devices', 'error');
        }
    }

    // Message Functions
    async sendQuickMessage(deviceId, messageType) {
        try {
            const payload = messageType === 'status' ? { statusType: 'health' } : {};
            
            const result = await this.apiCall('/messages/send', {
                method: 'POST',
                body: JSON.stringify({
                    deviceId: deviceId,
                    messageType: messageType,
                    payload: payload,
                    priority: 'normal'
                })
            });

            showToast(result.message, 'success');
            logActivity(`${messageType} message sent to ${deviceId}`, 'success');
        } catch (error) {
            logActivity(`Failed to send ${messageType} message to ${deviceId}`, 'error');
        }
    }

    async sendCustomMessage() {
        const deviceId = document.getElementById('modal-device-select')?.value;
        const messageType = document.getElementById('modal-message-type')?.value;
        const priority = document.getElementById('modal-priority')?.value;

        if (!deviceId) {
            showToast('Please select a device', 'warning');
            return;
        }

        let payload = {};

        // Build payload based on message type
        if (messageType === 'status') {
            payload.statusType = document.getElementById('status-type')?.value || 'health';
            payload.includeMetrics = document.getElementById('include-metrics')?.checked || false;
        } else if (messageType === 'update') {
            const propertiesText = document.getElementById('update-properties')?.value || '{}';
            try {
                payload.properties = JSON.parse(propertiesText);
                payload.configuration = JSON.parse(document.getElementById('update-config')?.value || '{}');
            } catch (e) {
                showToast('Invalid JSON in update data', 'error');
                return;
            }
        } else if (messageType === 'patch') {
            const patchText = document.getElementById('patch-data')?.value || '{}';
            try {
                payload.patchData = JSON.parse(patchText);
                payload.patchType = document.getElementById('patch-type')?.value || 'configuration';
                payload.rollbackEnabled = document.getElementById('rollback-enabled')?.checked || true;
            } catch (e) {
                showToast('Invalid JSON in patch data', 'error');
                return;
            }
        } else if (messageType === 'code') {
            payload.code = document.getElementById('code-content')?.value || '';
            payload.language = document.getElementById('code-language')?.value || 'python';
            payload.parameters = JSON.parse(document.getElementById('code-parameters')?.value || '{}');
        }

        try {
            const result = await this.apiCall('/messages/send', {
                method: 'POST',
                body: JSON.stringify({
                    deviceId: deviceId,
                    messageType: messageType,
                    payload: payload,
                    priority: priority
                })
            });

            showToast(result.message, 'success');
            logActivity(`Custom ${messageType} message sent to ${deviceId}`, 'success');
            closeMessageModal();
        } catch (error) {
            logActivity(`Failed to send custom message to ${deviceId}`, 'error');
        }
    }

    // Modal Functions
    openMessageModal() {
        const modal = document.getElementById('message-modal');
        const deviceSelect = document.getElementById('modal-device-select');
        
        // Populate device dropdown
        deviceSelect.innerHTML = this.devices.map(device => 
            `<option value="${device.deviceId}">${device.deviceId} (${device.deviceType})</option>`
        ).join('');
        
        updateModalForm();
        modal.classList.add('active');
    }

    openCodeModal(deviceId = null) {
        console.log('Opening code modal for device:', deviceId);
        const modal = document.getElementById('code-modal');
        const deviceSelect = document.getElementById('code-device-select');
        const deviceGroup = document.getElementById('code-device-group');
        
        if (!modal) {
            console.error('Code modal not found');
            showToast('Code modal not found', 'error');
            return;
        }
        
        if (deviceId) {
            // Single device mode
            deviceSelect.innerHTML = `<option value="${deviceId}">${deviceId}</option>`;
            deviceSelect.disabled = true;
            deviceGroup.style.display = 'block';
        } else {
            // Multiple device mode - show selected devices or all
            const selectedDevices = this.getSelectedDevices();
            const targetDevices = selectedDevices.length > 0 ? selectedDevices : this.devices.map(d => d.deviceId);
            
            deviceSelect.innerHTML = targetDevices.map(id => {
                const device = this.devices.find(d => d.deviceId === id);
                return `<option value="${id}">${id} (${device ? device.deviceType : 'Unknown'})</option>`;
            }).join('');
            deviceSelect.disabled = false;
            deviceGroup.style.display = targetDevices.length === 1 ? 'block' : 'none';
        }
        
        // Set default code template
        try {
            loadCodeTemplate();
        } catch (error) {
            console.error('Error loading code template:', error);
        }
        
        modal.classList.add('active');
        console.log('Code modal opened successfully');
    }

    openPatchModal(deviceId = null) {
        const modal = document.getElementById('patch-modal');
        const deviceSelect = document.getElementById('patch-device-select');
        const deviceGroup = document.getElementById('patch-device-group');
        
        if (deviceId) {
            // Single device mode
            deviceSelect.innerHTML = `<option value="${deviceId}">${deviceId}</option>`;
            deviceSelect.disabled = true;
            deviceGroup.style.display = 'block';
        } else {
            // Multiple device mode - show selected devices or all
            const selectedDevices = this.getSelectedDevices();
            const targetDevices = selectedDevices.length > 0 ? selectedDevices : this.devices.map(d => d.deviceId);
            
            deviceSelect.innerHTML = targetDevices.map(id => {
                const device = this.devices.find(d => d.deviceId === id);
                return `<option value="${id}">${id} (${device ? device.deviceType : 'Unknown'})</option>`;
            }).join('');
            deviceSelect.disabled = false;
            deviceGroup.style.display = targetDevices.length === 1 ? 'block' : 'none';
        }
        
        // Set default patch template
        loadPatchTemplate();
        modal.classList.add('active');
    }

    openDeviceModal(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) return;

        const modal = document.getElementById('device-modal');
        const content = document.getElementById('device-modal-content');
        
        content.innerHTML = `
            <div class="device-details">
                <div class="detail-card">
                    <h4><i class="fas fa-info-circle"></i> Basic Information</h4>
                    <div class="detail-item">
                        <span class="detail-label">Device ID:</span>
                        <span class="detail-value">${device.deviceId}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Device Type:</span>
                        <span class="detail-value">${device.deviceType}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Manufacturer:</span>
                        <span class="detail-value">${device.manufacturer}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Status:</span>
                        <span class="status-indicator ${device.status === 'Connected' ? 'online' : 'offline'}">
                            <i class="fas fa-circle"></i>
                            ${device.status}
                        </span>
                    </div>
                </div>
                
                <div class="detail-card">
                    <h4><i class="fas fa-cogs"></i> System Information</h4>
                    <div class="detail-item">
                        <span class="detail-label">Operating System:</span>
                        <span class="detail-value">${device.osName} ${device.osVersion}</span>
                    </div>
                </div>

                <div class="detail-card">
                    <h4><i class="fas fa-link"></i> Connection</h4>
                    <div class="detail-item">
                        <span class="detail-label">Connection String:</span>
                        <span class="detail-value" style="word-break: break-all; font-size: 0.7rem;">
                            ${device.connectionString.substring(0, 50)}...
                        </span>
                    </div>
                </div>

                <div class="detail-card">
                    <h4><i class="fas fa-paper-plane"></i> Quick Actions</h4>
                    <div class="button-group">
                        <button class="btn btn-primary" onclick="deviceManager.sendQuickMessage('${deviceId}', 'normal')">
                            <i class="fas fa-heartbeat"></i> Send Telemetry
                        </button>
                        <button class="btn btn-info" onclick="deviceManager.sendQuickMessage('${deviceId}', 'status')">
                            <i class="fas fa-check-circle"></i> Check Status
                        </button>
                        <button class="btn btn-warning" onclick="deviceManager.checkDeviceHealth('${deviceId}')">
                            <i class="fas fa-stethoscope"></i> Health Check
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        modal.classList.add('active');
    }

    async checkDeviceHealth(deviceId) {
        try {
            const result = await this.apiCall(`/devices/${deviceId}/status`, {
                method: 'POST',
                body: JSON.stringify({
                    deviceId: deviceId,
                    statusType: 'all'
                })
            });

            showToast(`Health check completed for ${deviceId}`, 'success');
            logActivity(`Health check: ${JSON.stringify(result.data)}`, 'info');
        } catch (error) {
            logActivity(`Health check failed for ${deviceId}`, 'error');
        }
    }

    // Telemetry Functions
    async sendTelemetry() {
        const selectedDevices = this.getSelectedDevices();
        const messageCount = parseInt(document.getElementById('message-count')?.value || '5');

        try {
            const result = await this.apiCall('/telemetry/send', {
                method: 'POST',
                body: JSON.stringify({
                    deviceIds: selectedDevices.length > 0 ? selectedDevices : null,
                    messageCount
                })
            });

            showToast(result.message, 'success');
            logActivity(`Sent ${result.data.total_messages} telemetry messages`, 'success');
        } catch (error) {
            logActivity('Failed to send telemetry', 'error');
        }
    }

    async sendSampleTelemetry(deviceId, deviceType) {
        try {
            // First get sample data to show what will be sent
            const sampleResult = await this.apiCall(`/telemetry/sample/${deviceType}`);
            
            // Then send actual telemetry
            const result = await this.apiCall('/telemetry/send', {
                method: 'POST',
                body: JSON.stringify({
                    deviceIds: [deviceId],
                    messageCount: 1
                })
            });

            showToast(`Sample telemetry sent from ${deviceId}`, 'success');
            logActivity(`Sent sample telemetry from ${deviceId}: ${JSON.stringify(sampleResult.data)}`, 'info');
        } catch (error) {
            logActivity(`Failed to send sample telemetry from ${deviceId}`, 'error');
        }
    }

    async startContinuous() {
        const selectedDevices = this.getSelectedDevices();
        const interval = parseFloat(document.getElementById('interval')?.value || '10');
        const duration = parseFloat(document.getElementById('duration')?.value || '60');

        try {
            const result = await this.apiCall('/telemetry/continuous', {
                method: 'POST',
                body: JSON.stringify({
                    deviceIds: selectedDevices.length > 0 ? selectedDevices : null,
                    interval,
                    duration
                })
            });

            this.continuousActive = true;
            this.updateContinuousUI();
            showToast(result.message, 'success');
            logActivity(`Started continuous telemetry (${interval}s interval, ${duration}s duration)`, 'success');

            // Auto-stop after duration
            setTimeout(() => {
                this.stopContinuous();
            }, duration * 1000);

        } catch (error) {
            logActivity('Failed to start continuous telemetry', 'error');
        }
    }

    stopContinuous() {
        this.continuousActive = false;
        this.updateContinuousUI();
        showToast('Continuous telemetry stopped', 'warning');
        logActivity('Stopped continuous telemetry', 'warning');
    }

    updateContinuousUI() {
        const startBtn = document.querySelector('button[onclick="startContinuous()"]');
        const stopBtn = document.querySelector('button[onclick="stopContinuous()"]');

        if (startBtn) startBtn.disabled = this.continuousActive;
        if (stopBtn) stopBtn.disabled = !this.continuousActive;
    }

    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.querySelector('button[onclick="refreshDevices()"]');
        if (refreshBtn) {
            refreshBtn.onclick = () => this.loadDevices();
        }

        // Filter change
        const filter = document.getElementById('device-filter');
        if (filter) {
            filter.onchange = () => this.filterDevices();
        }
    }
}

// Utility Functions
function showLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.classList.toggle('active', show);
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };

    toast.innerHTML = `
        <div class="toast-content">
            <i class="${icons[type] || icons.info}"></i>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;

    container.appendChild(toast);
    
    // Show toast
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, 5000);
}

function logActivity(message, type = 'info') {
    const log = document.getElementById('activity-log');
    if (!log) return;

    const entry = document.createElement('div');
    entry.className = `activity-entry activity-${type}`;
    
    const timestamp = new Date().toLocaleTimeString();
    const icons = {
        success: 'fas fa-check',
        error: 'fas fa-times',
        warning: 'fas fa-exclamation',
        info: 'fas fa-info'
    };

    entry.innerHTML = `
        <span class="activity-icon">
            <i class="${icons[type] || icons.info}"></i>
        </span>
        <span class="activity-time">${timestamp}</span>
        <span class="activity-message">${message}</span>
    `;

    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;

    // Keep only last 100 entries
    while (log.children.length > 100) {
        log.removeChild(log.firstChild);
    }
}

function clearLog() {
    const log = document.getElementById('activity-log');
    if (log) {
        log.innerHTML = '';
        showToast('Activity log cleared', 'info');
    }
}

// Modal and Form Functions
function openMessageModal() {
    deviceManager.openMessageModal();
}

function closeMessageModal() {
    const modal = document.getElementById('message-modal');
    modal.classList.remove('active');
}

function closeDeviceModal() {
    const modal = document.getElementById('device-modal');
    modal.classList.remove('active');
}

function updateMessageForm() {
    const messageType = document.getElementById('message-type')?.value;
    updateModalForm(messageType);
}

function updateModalForm(messageType) {
    if (!messageType) {
        messageType = document.getElementById('modal-message-type')?.value;
    }
    
    const content = document.getElementById('dynamic-form-content');
    if (!content) return;

    let formHTML = '';

    switch (messageType) {
        case 'normal':
            formHTML = `
                <div class="form-section">
                    <h4><i class="fas fa-chart-line"></i> Telemetry Request</h4>
                    <p class="help-text">This will request the device to send current telemetry data.</p>
                </div>
            `;
            break;

        case 'status':
            formHTML = `
                <div class="form-section">
                    <h4><i class="fas fa-check-circle"></i> Status Check</h4>
                    <div class="input-group">
                        <label for="status-type">Status Type:</label>
                        <select id="status-type">
                            <option value="health">Health Status</option>
                            <option value="connectivity">Connectivity</option>
                            <option value="battery">Battery Level</option>
                            <option value="sensors">Sensor Status</option>
                            <option value="all">All Status</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>
                            <input type="checkbox" id="include-metrics" checked>
                            Include performance metrics
                        </label>
                        <label>
                            <input type="checkbox" id="include-logs">
                            Include recent logs
                        </label>
                    </div>
                </div>
            `;
            break;

        case 'update':
            formHTML = `
                <div class="form-section">
                    <h4><i class="fas fa-upload"></i> Device Update</h4>
                    <div class="input-group">
                        <label for="update-properties">Device Properties (JSON):</label>
                        <div class="json-editor">
                            <textarea id="update-properties" placeholder='{"manufacturer": "New Manufacturer", "firmware": "1.2.3"}'></textarea>
                        </div>
                        <div class="help-text">JSON object with properties to update</div>
                    </div>
                    <div class="input-group">
                        <label for="update-config">Configuration (JSON):</label>
                        <div class="json-editor">
                            <textarea id="update-config" placeholder='{"interval": 30, "threshold": 100}'></textarea>
                        </div>
                        <div class="help-text">Device configuration parameters</div>
                    </div>
                </div>
            `;
            break;

        case 'patch':
            formHTML = `
                <div class="form-section">
                    <h4><i class="fas fa-band-aid"></i> Device Patch</h4>
                    <div class="input-group">
                        <label for="patch-type">Patch Type:</label>
                        <select id="patch-type">
                            <option value="configuration">Configuration</option>
                            <option value="firmware">Firmware</option>
                            <option value="security">Security</option>
                            <option value="feature">Feature Update</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label for="patch-data">Patch Data (JSON):</label>
                        <div class="json-editor">
                            <textarea id="patch-data" placeholder='{"version": "1.0.1", "changes": ["bug_fix_001", "security_patch_002"]}'></textarea>
                        </div>
                        <div class="help-text">Patch details and data</div>
                    </div>
                    <label>
                        <input type="checkbox" id="rollback-enabled" checked>
                        Enable automatic rollback on failure
                    </label>
                </div>
            `;
            break;

        case 'code':
            formHTML = `
                <div class="form-section">
                    <h4><i class="fas fa-code"></i> Code Execution</h4>
                    <div class="input-group">
                        <label for="code-language">Programming Language:</label>
                        <select id="code-language">
                            <option value="python">Python</option>
                            <option value="javascript">JavaScript</option>
                            <option value="shell">Shell Script</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label for="code-content">Code to Execute:</label>
                        <div class="code-editor">
                            <textarea id="code-content" placeholder="print('Hello from device!')"></textarea>
                        </div>
                        <div class="help-text">Code will be executed on the target device</div>
                    </div>
                    <div class="input-group">
                        <label for="code-parameters">Parameters (JSON):</label>
                        <div class="json-editor">
                            <textarea id="code-parameters" placeholder='{"arg1": "value1", "timeout": 30}'></textarea>
                        </div>
                        <div class="help-text">Parameters to pass to the code</div>
                    </div>
                </div>
            `;
            break;
    }

    content.innerHTML = formHTML;
}

function sendCustomMessage() {
    deviceManager.sendCustomMessage();
}

// Code Modal Functions
function openCodeModal(deviceId) {
    console.log('Global openCodeModal called with deviceId:', deviceId);
    if (!deviceManager) {
        console.error('DeviceManager not initialized');
        showToast('Device manager not ready', 'error');
        return;
    }
    deviceManager.openCodeModal(deviceId);
}

function closeCodeModal() {
    const modal = document.getElementById('code-modal');
    modal.classList.remove('active');
}

function updateCodeTemplate() {
    loadCodeTemplate();
}

function loadCodeTemplate() {
    console.log('Loading code template...');
    const template = document.getElementById('code-template')?.value || 'custom';
    const language = document.getElementById('code-language-select')?.value || 'python';
    const codeContent = document.getElementById('quick-code-content');
    
    console.log('Template:', template, 'Language:', language);
    
    if (!codeContent) {
        console.error('Code content textarea not found');
        return;
    }

    const templates = {
        python: {
            custom: '# Enter your Python code here\nprint("Hello from device!")',
            health_check: `# Device Health Check Script
import json
import time

def check_device_health():
    health_data = {
        "timestamp": time.time(),
        "cpu_usage": 45.2,
        "memory_usage": 67.8,
        "temperature": 25.4,
        "battery_level": 89,
        "status": "healthy"
    }
    print(json.dumps(health_data, indent=2))
    return health_data

check_device_health()`,
            sensor_calibration: `# Sensor Calibration Script
import time

def calibrate_sensors():
    print("Starting sensor calibration...")
    sensors = ["temperature", "pressure", "humidity"]
    
    for sensor in sensors:
        print(f"Calibrating {sensor} sensor...")
        time.sleep(1)  # Simulate calibration time
        print(f"{sensor} sensor calibrated successfully")
    
    print("All sensors calibrated!")

calibrate_sensors()`,
            diagnostic: `# Device Diagnostic Script
import json
import random

def run_diagnostics():
    tests = {
        "memory_test": random.choice([True, True, False]),
        "sensor_test": random.choice([True, True, True]),
        "network_test": random.choice([True, False]),
        "battery_test": True
    }
    
    print("Running diagnostics...")
    for test, result in tests.items():
        status = "PASS" if result else "FAIL"
        print(f"{test}: {status}")
    
    return tests

run_diagnostics()`,
            config_update: `# Configuration Update Script
import json

def update_config():
    new_config = {
        "sampling_rate": 1000,
        "data_retention": 30,
        "alert_threshold": 75,
        "auto_backup": True
    }
    
    print("Updating device configuration...")
    print(json.dumps(new_config, indent=2))
    print("Configuration updated successfully!")

update_config()`
        },
        javascript: {
            custom: '// Enter your JavaScript code here\nconsole.log("Hello from device!");',
            health_check: `// Device Health Check Script
function checkDeviceHealth() {
    const healthData = {
        timestamp: Date.now(),
        cpuUsage: 45.2,
        memoryUsage: 67.8,
        temperature: 25.4,
        batteryLevel: 89,
        status: "healthy"
    };
    console.log(JSON.stringify(healthData, null, 2));
    return healthData;
}

checkDeviceHealth();`,
            sensor_calibration: `// Sensor Calibration Script
function calibrateSensors() {
    console.log("Starting sensor calibration...");
    const sensors = ["temperature", "pressure", "humidity"];
    
    sensors.forEach((sensor, index) => {
        setTimeout(() => {
            console.log(\`Calibrating \${sensor} sensor...\`);
            console.log(\`\${sensor} sensor calibrated successfully\`);
            if (index === sensors.length - 1) {
                console.log("All sensors calibrated!");
            }
        }, index * 1000);
    });
}

calibrateSensors();`,
            diagnostic: 'console.log("JavaScript diagnostic template");',
            config_update: 'console.log("JavaScript config update template");'
        },
        shell: {
            custom: '#!/bin/bash\n# Enter your shell script here\necho "Hello from device!"',
            health_check: `#!/bin/bash
# Device Health Check Script
echo "Running device health check..."

CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')
TEMPERATURE=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "25000")
BATTERY=$(cat /sys/class/power_supply/BAT*/capacity 2>/dev/null || echo "100")

echo "Health Status:"
echo "CPU Usage: ${CPU_USAGE}%"
echo "Memory Usage: ${MEMORY_USAGE}%"
echo "Temperature: $((TEMPERATURE/1000))°C"
echo "Battery: ${BATTERY}%"`,
            sensor_calibration: `#!/bin/bash
# Sensor Calibration Script
echo "Starting sensor calibration..."

sensors=("temperature" "pressure" "humidity")
for sensor in "\${sensors[@]}"; do
    echo "Calibrating $sensor sensor..."
    sleep 1
    echo "$sensor sensor calibrated successfully"
done

echo "All sensors calibrated!"`,
            diagnostic: '#!/bin/bash\necho "Running shell diagnostics..."',
            config_update: '#!/bin/bash\necho "Updating configuration via shell..."'
        }
    };

    const code = templates[language]?.[template] || templates[language]?.custom || '';
    codeContent.value = code;
}

async function sendCodeMessage() {
    const deviceId = document.getElementById('code-device-select')?.value;
    const language = document.getElementById('code-language-select')?.value;
    const code = document.getElementById('quick-code-content')?.value;
    const timeout = parseInt(document.getElementById('code-timeout')?.value || '30');

    if (!deviceId || !code.trim()) {
        showToast('Please select a device and enter code to execute', 'warning');
        return;
    }

    try {
        const result = await deviceManager.apiCall('/messages/send', {
            method: 'POST',
            body: JSON.stringify({
                deviceId: deviceId,
                messageType: 'code',
                payload: {
                    code: code.trim(),
                    language: language,
                    parameters: {}
                },
                priority: 'normal',
                timeout: timeout
            })
        });

        showToast(result.message, 'success');
        logActivity(`Code executed on ${deviceId} (${language})`, 'success');
        closeCodeModal();
    } catch (error) {
        logActivity(`Failed to execute code on ${deviceId}`, 'error');
    }
}

// Patch Modal Functions
function openPatchModal(deviceId) {
    console.log('Global openPatchModal called with deviceId:', deviceId);
    if (!deviceManager) {
        console.error('DeviceManager not initialized');
        showToast('Device manager not ready', 'error');
        return;
    }
    deviceManager.openPatchModal(deviceId);
}

function closePatchModal() {
    const modal = document.getElementById('patch-modal');
    modal.classList.remove('active');
}

function updatePatchTemplate() {
    loadPatchTemplate();
}

function loadPatchTemplate() {
    const template = document.getElementById('patch-template')?.value;
    const patchType = document.getElementById('patch-type-select')?.value || 'configuration';
    const patchContent = document.getElementById('quick-patch-content');
    const versionField = document.getElementById('patch-version');
    
    if (!patchContent) return;

    const templates = {
        custom: '{\n  "version": "1.0.1",\n  "changes": ["custom_change_001"],\n  "description": "Custom patch"\n}',
        config_reset: `{
  "version": "1.0.0-reset",
  "changes": ["reset_to_defaults"],
  "description": "Reset device configuration to factory defaults",
  "config": {
    "sampling_rate": 1000,
    "alert_threshold": 80,
    "auto_backup": true,
    "log_level": "info"
  }
}`,
        sensor_update: `{
  "version": "1.1.0-sensors",
  "changes": ["sensor_calibration_update", "threshold_adjustment"],
  "description": "Update sensor calibration and thresholds",
  "sensors": {
    "temperature": {
      "calibration_offset": 0.5,
      "threshold_high": 40.0,
      "threshold_low": 10.0
    },
    "pressure": {
      "calibration_factor": 1.02,
      "threshold_high": 1100,
      "threshold_low": 900
    }
  }
}`,
        security_patch: `{
  "version": "1.0.1-security",
  "changes": ["CVE-2024-001", "authentication_fix"],
  "description": "Security patch for authentication vulnerability",
  "security": {
    "certificate_update": true,
    "encryption_algorithm": "AES-256",
    "key_rotation": true,
    "access_control": "strict"
  }
}`,
        performance_tune: `{
  "version": "1.0.1-perf",
  "changes": ["cpu_optimization", "memory_management"],
  "description": "Performance tuning and optimization",
  "performance": {
    "cpu_governor": "performance",
    "memory_optimization": true,
    "cache_size": 128,
    "thread_pool_size": 4
  }
}`
    };

    const patchData = templates[template] || templates.custom;
    patchContent.value = patchData;
    
    // Update version field based on template
    if (versionField) {
        const parsed = JSON.parse(patchData);
        versionField.value = parsed.version || '1.0.0';
    }
}

async function sendPatchMessage() {
    const deviceId = document.getElementById('patch-device-select')?.value;
    const patchType = document.getElementById('patch-type-select')?.value;
    const patchData = document.getElementById('quick-patch-content')?.value;
    const rollbackEnabled = document.getElementById('patch-rollback')?.checked;
    const backupEnabled = document.getElementById('patch-backup')?.checked;

    if (!deviceId || !patchData.trim()) {
        showToast('Please select a device and enter patch data', 'warning');
        return;
    }

    let parsedPatchData;
    try {
        parsedPatchData = JSON.parse(patchData);
    } catch (e) {
        showToast('Invalid JSON in patch data', 'error');
        return;
    }

    try {
        const result = await deviceManager.apiCall('/messages/send', {
            method: 'POST',
            body: JSON.stringify({
                deviceId: deviceId,
                messageType: 'patch',
                payload: {
                    patchData: parsedPatchData,
                    patchType: patchType,
                    rollbackEnabled: rollbackEnabled,
                    backupEnabled: backupEnabled
                },
                priority: 'high'
            })
        });

        showToast(result.message, 'success');
        logActivity(`Patch applied to ${deviceId} (${patchType})`, 'success');
        closePatchModal();
    } catch (error) {
        logActivity(`Failed to apply patch to ${deviceId}`, 'error');
    }
}

// Quick Actions
function sendStatusToAll() {
    deviceManager.devices.forEach(device => {
        deviceManager.sendQuickMessage(device.deviceId, 'status');
    });
}

// Global Functions (called from HTML)
function refreshDevices() {
    deviceManager.loadDevices();
}

function connectAllDevices() {
    deviceManager.connectAllDevices();
}

function disconnectAllDevices() {
    deviceManager.disconnectAllDevices();
}

function sendTelemetry() {
    deviceManager.sendTelemetry();
}

function startContinuous() {
    deviceManager.startContinuous();
}

function stopContinuous() {
    deviceManager.stopContinuous();
}

function filterDevices() {
    deviceManager.filterDevices();
}

// Initialize when DOM is loaded
let deviceManager;

document.addEventListener('DOMContentLoaded', () => {
    deviceManager = new DeviceManager();
    logActivity('Medical IoT Device Manager initialized', 'success');
    
    // Add modal close functionality when clicking outside
    document.addEventListener('click', (event) => {
        if (event.target.classList.contains('modal-overlay')) {
            event.target.classList.remove('active');
        }
    });
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && deviceManager) {
        // Refresh when page becomes visible
        deviceManager.loadDevices();
    }
});

// Error handling for unhandled promises
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showToast('An unexpected error occurred', 'error');
    logActivity(`Unhandled error: ${event.reason}`, 'error');
});