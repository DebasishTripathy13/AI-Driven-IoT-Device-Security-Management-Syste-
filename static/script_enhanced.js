// Enhanced Medical IoT Dashboard - JavaScript
// Modern, responsive, and feature-rich device management

class MedicalIoTDashboard {
    constructor() {
        this.devices = [];
        this.selectedDevices = new Set();
        this.currentView = 'grid';
        this.continuousTelemetry = null;
        this.refreshInterval = null;
        this.wsConnection = null;
        
        this.init();
    }

    async init() {
        await this.showLoadingScreen();
        await this.loadDevices();
        await this.loadSecurityStats();
        this.setupEventListeners();
        this.startAutoRefresh();
        this.hideLoadingScreen();
        this.showWelcomeToast();
    }

    // Loading Screen Management
    async showLoadingScreen() {
        const loadingScreen = document.getElementById('loading-screen');
        const progressBar = loadingScreen.querySelector('.loading-progress');
        
        // Animate progress bar
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 30;
            if (progress > 100) progress = 100;
            progressBar.style.width = progress + '%';
            
            if (progress >= 100) {
                clearInterval(interval);
            }
        }, 200);
        
        await this.delay(2000); // Simulate loading time
    }

    hideLoadingScreen() {
        const loadingScreen = document.getElementById('loading-screen');
        loadingScreen.style.opacity = '0';
        setTimeout(() => {
            loadingScreen.style.display = 'none';
        }, 500);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Device Management
    async loadDevices() {
        try {
            this.showToast('Loading devices...', 'info');
            const response = await fetch('/api/devices');
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            this.devices = await response.json();
            this.updateDeviceStats();
            this.renderDevices();
            this.populateDeviceSelects();
            this.showToast(`Loaded ${this.devices.length} medical devices`, 'success');
            
        } catch (error) {
            console.error('Error loading devices:', error);
            this.showToast('Failed to load devices: ' + error.message, 'error');
            this.addActivityLog('Error loading devices: ' + error.message, 'error');
        }
    }

    updateDeviceStats() {
        const connectedCount = this.devices.filter(d => d.status === 'Connected').length;
        const totalCount = this.devices.length;
        const disconnectedCount = totalCount - connectedCount;
        
        // Update header stats with real data
        document.getElementById('device-count').textContent = `${totalCount} Devices`;
        document.getElementById('connection-status').textContent = `${connectedCount}/${totalCount} Connected`;
        
        // Update control panel stats
        document.getElementById('connected-devices').textContent = connectedCount;
        document.getElementById('total-devices').textContent = totalCount;
        
        // Update connection status color based on ratio
        const connectionStatusElement = document.getElementById('connection-status');
        const connectionRatio = connectedCount / totalCount;
        
        if (connectionRatio >= 0.8) {
            connectionStatusElement.style.color = 'var(--success-color)';
        } else if (connectionRatio >= 0.5) {
            connectionStatusElement.style.color = 'var(--warning-color)';
        } else {
            connectionStatusElement.style.color = 'var(--error-color)';
        }
        
        // Add activity log entry for status updates
        if (totalCount > 0) {
            this.addActivityLog(`Device Status: ${connectedCount} connected, ${disconnectedCount} disconnected`, 'info');
        }
    }

    renderDevices() {
        const container = document.getElementById('devices-container');
        if (!container) return;

        if (this.devices.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-hospital"></i>
                    <h3>No devices found</h3>
                    <p>Please register some medical devices first</p>
                    <button class="btn btn-primary" onclick="window.location.reload()">
                        <i class="fas fa-refresh"></i> Refresh
                    </button>
                </div>
            `;
            return;
        }

        container.innerHTML = this.devices.map(device => this.createDeviceCard(device)).join('');
        
        // Apply current view
        container.className = this.currentView === 'grid' ? 'device-grid' : 'device-list';
    }

    createDeviceCard(device) {
        const isConnected = device.status === 'Connected';
        const deviceTypeIcon = this.getDeviceIcon(device.deviceType);
        const isSelected = this.selectedDevices.has(device.deviceId);
        
        return `
            <div class="device-card ${isSelected ? 'selected' : ''}" data-device-id="${device.deviceId}">
                <div class="device-header">
                    <div class="device-info">
                        <div class="device-icon">
                            <i class="${deviceTypeIcon}"></i>
                        </div>
                        <div class="device-details-summary">
                            <h3>${device.deviceId}</h3>
                            <p class="device-type">${device.deviceType}</p>
                            <p class="device-manufacturer">${device.manufacturer}</p>
                        </div>
                    </div>
                    <div class="device-status ${isConnected ? 'connected' : 'disconnected'}">
                        ${isConnected ? 'Connected' : 'Disconnected'}
                    </div>
                </div>
                
                <div class="device-details">
                    <div class="detail-row">
                        <span class="detail-label">Operating System:</span>
                        <span class="detail-value">${device.osName} ${device.osVersion}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Manufacturer:</span>
                        <span class="detail-value">${device.manufacturer}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Connection:</span>
                        <span class="detail-value ${isConnected ? 'status-connected' : 'status-disconnected'}">
                            <i class="fas ${isConnected ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                            ${device.status}
                        </span>
                    </div>
                </div>
                
                <div class="device-actions">
                    <!-- Primary Actions Row -->
                    <div class="action-row primary-actions">
                        <button class="btn btn-sm ${isSelected ? 'btn-warning' : 'btn-secondary'}" 
                                onclick="dashboard.toggleDeviceSelection('${device.deviceId}')" 
                                title="${isSelected ? 'Deselect device' : 'Select device'}">
                            <i class="fas ${isSelected ? 'fa-check-square' : 'fa-square'}"></i>
                            ${isSelected ? 'Selected' : 'Select'}
                        </button>
                        
                        <button class="btn btn-sm ${isConnected ? 'btn-danger' : 'btn-success'}" 
                                onclick="dashboard.toggleDeviceConnection('${device.deviceId}')"
                                title="${isConnected ? 'Disconnect device' : 'Connect device'}">
                            <i class="fas ${isConnected ? 'fa-unlink' : 'fa-link'}"></i>
                            ${isConnected ? 'Disconnect' : 'Connect'}
                        </button>
                        
                        <button class="btn btn-sm btn-primary" 
                                onclick="dashboard.sendTelemetryToDevice('${device.deviceId}')"
                                title="Send telemetry data">
                            <i class="fas fa-paper-plane"></i>
                            Telemetry
                        </button>
                    </div>
                    
                    <!-- Secondary Actions Row -->
                    <div class="action-row secondary-actions">
                        <button class="btn btn-sm btn-info" 
                                onclick="dashboard.sendCodeToDevice('${device.deviceId}')"
                                title="Execute code on device"
                                ${!isConnected ? 'disabled' : ''}>
                            <i class="fas fa-code"></i>
                            Send Code
                        </button>
                        
                        <button class="btn btn-sm btn-warning" 
                                onclick="dashboard.sendPatchToDevice('${device.deviceId}')"
                                title="Deploy patch to device"
                                ${!isConnected ? 'disabled' : ''}>
                            <i class="fas fa-download"></i>
                            Send Patch
                        </button>
                        
                        <button class="btn btn-sm btn-success" 
                                onclick="dashboard.checkDeviceStatus('${device.deviceId}')"
                                title="Check device health">
                            <i class="fas fa-stethoscope"></i>
                            Health Check
                        </button>
                    </div>
                    
                    <!-- Tertiary Actions Row -->
                    <div class="action-row tertiary-actions">
                        <button class="btn btn-sm btn-secondary" 
                                onclick="dashboard.openDeviceDetails('${device.deviceId}')"
                                title="View device details">
                            <i class="fas fa-info-circle"></i>
                            Details
                        </button>
                        
                        <button class="btn btn-sm btn-purple" 
                                onclick="dashboard.sendCustomMessage('${device.deviceId}')"
                                title="Send custom message"
                                ${!isConnected ? 'disabled' : ''}>
                            <i class="fas fa-envelope"></i>
                            Message
                        </button>
                        
                        <button class="btn btn-sm btn-dark" 
                                onclick="dashboard.restartDevice('${device.deviceId}')"
                                title="Restart device"
                                ${!isConnected ? 'disabled' : ''}>
                            <i class="fas fa-power-off"></i>
                            Restart
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    getDeviceIcon(deviceType) {
        const icons = {
            'ECG': 'fas fa-heartbeat',
            'BloodPressureMonitor': 'fas fa-tint',
            'PulseOximeter': 'fas fa-lungs',
            'Glucometer': 'fas fa-vial',
            'Thermometer': 'fas fa-thermometer-half',
            'InfusionPump': 'fas fa-syringe',
            'Ventilator': 'fas fa-wind',  
            'Defibrillator': 'fas fa-bolt',
            'EEG': 'fas fa-brain',
            'Ultrasound': 'fas fa-sound'
        };
        return icons[deviceType] || 'fas fa-medical';
    }

    // Device Selection Management
    toggleDeviceSelection(deviceId) {
        if (this.selectedDevices.has(deviceId)) {
            this.selectedDevices.delete(deviceId);
        } else {
            this.selectedDevices.add(deviceId);
        }
        this.renderDevices();
        this.updateSelectionInfo();
    }

    updateSelectionInfo() {
        const count = this.selectedDevices.size;
        if (count > 0) {
            this.showToast(`${count} device${count > 1 ? 's' : ''} selected`, 'info');
        }
    }

    // Device Connection Management
    async toggleDeviceConnection(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) return;

        const isConnected = device.status === 'Connected';
        const action = isConnected ? 'disconnect' : 'connect';
        
        try {
            this.showToast(`${isConnected ? 'Disconnecting' : 'Connecting'} ${deviceId}...`, 'info');
            
            const response = await fetch(`/api/devices/${action}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ deviceIds: [deviceId] })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            this.addActivityLog(`${action.charAt(0).toUpperCase() + action.slice(1)}ed ${deviceId}`, 'success');
            
            // Refresh device status
            await this.loadDevices();
            
        } catch (error) {
            console.error(`Error ${action}ing device:`, error);
            this.showToast(`Failed to ${action} device: ${error.message}`, 'error');
            this.addActivityLog(`Failed to ${action} ${deviceId}: ${error.message}`, 'error');
        }
    }

    // Bulk Operations
    async connectAllDevices() {
        const deviceIds = this.devices.map(d => d.deviceId);
        await this.bulkConnect(deviceIds);
    }

    async disconnectAllDevices() {
        const connectedDevices = this.devices.filter(d => d.status === 'Connected').map(d => d.deviceId);
        await this.bulkDisconnect(connectedDevices);
    }

    async bulkConnect(deviceIds) {
        if (deviceIds.length === 0) {
            this.showToast('No devices to connect', 'warning');
            return;
        }

        try {
            this.showToast(`Connecting ${deviceIds.length} devices...`, 'info');
            
            const response = await fetch('/api/devices/connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ deviceIds })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            this.addActivityLog(`Bulk connect: ${result.message}`, 'success');
            
            await this.loadDevices();

        } catch (error) {
            console.error('Error connecting devices:', error);
            this.showToast('Failed to connect devices: ' + error.message, 'error');
            this.addActivityLog('Bulk connect failed: ' + error.message, 'error');
        }
    }

    async bulkDisconnect(deviceIds) {
        if (deviceIds.length === 0) {
            this.showToast('No connected devices to disconnect', 'warning');
            return;
        }

        try {
            this.showToast(`Disconnecting ${deviceIds.length} devices...`, 'info');
            
            const response = await fetch('/api/devices/disconnect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ deviceIds })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            this.addActivityLog(`Bulk disconnect: ${result.message}`, 'success');
            
            await this.loadDevices();

        } catch (error) {
            console.error('Error disconnecting devices:', error);
            this.showToast('Failed to disconnect devices: ' + error.message, 'error');
            this.addActivityLog('Bulk disconnect failed: ' + error.message, 'error');
        }
    }

    // Telemetry Operations
    async sendTelemetryBatch() {
        const selectedDeviceIds = Array.from(this.selectedDevices);
        const deviceIds = selectedDeviceIds.length > 0 ? selectedDeviceIds : this.devices.map(d => d.deviceId);
        const dataPoints = parseInt(document.getElementById('telemetry-count').value) || 5;

        if (deviceIds.length === 0) {
            this.showToast('No devices available for telemetry', 'warning');
            return;
        }

        try {
            this.showToast(`Sending ${dataPoints} data points to ${deviceIds.length} devices...`, 'info');
            
            const response = await fetch('/api/telemetry/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    deviceIds,
                    messageCount: dataPoints
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            this.addActivityLog(`Telemetry batch sent to ${deviceIds.length} devices`, 'success');

        } catch (error) {
            console.error('Error sending telemetry:', error);
            this.showToast('Failed to send telemetry: ' + error.message, 'error');
            this.addActivityLog('Telemetry batch failed: ' + error.message, 'error');
        }
    }

    async startContinuousTelemetry() {
        const interval = parseInt(document.getElementById('telemetry-interval').value) || 30;
        const selectedDeviceIds = Array.from(this.selectedDevices);
        const deviceIds = selectedDeviceIds.length > 0 ? selectedDeviceIds : this.devices.map(d => d.deviceId);

        if (this.continuousTelemetry) {
            // Stop continuous telemetry
            clearInterval(this.continuousTelemetry);
            this.continuousTelemetry = null;
            this.showToast('Continuous telemetry stopped', 'info');
            this.addActivityLog('Continuous telemetry stopped', 'info');
            
            // Update button text
            const btn = event.target;
            btn.innerHTML = '<i class="fas fa-play"></i> Start Continuous';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-secondary');
            return;
        }

        try {
            this.showToast(`Starting continuous telemetry (${interval}s interval)...`, 'info');
            
            this.continuousTelemetry = setInterval(async () => {
                try {
                    const response = await fetch('/api/telemetry/send', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            deviceIds,
                            messageCount: 1
                        })
                    });

                    if (response.ok) {
                        this.addActivityLog(`Continuous telemetry sent to ${deviceIds.length} devices`, 'info');
                    }
                } catch (error) {
                    console.error('Continuous telemetry error:', error);
                }
            }, interval * 1000);

            this.addActivityLog(`Continuous telemetry started (${interval}s interval)`, 'success');
            this.showToast('Continuous telemetry started', 'success');
            
            // Update button text
            const btn = event.target;
            btn.innerHTML = '<i class="fas fa-stop"></i> Stop Continuous';
            btn.classList.remove('btn-secondary');
            btn.classList.add('btn-danger');

        } catch (error) {
            console.error('Error starting continuous telemetry:', error);
            this.showToast('Failed to start continuous telemetry: ' + error.message, 'error');
        }
    }

    // Modal Management
    openBulkCodeModal() {
        this.populateDeviceSelect('code-target-devices');
        this.openModal('codeModal');
    }

    openBulkPatchModal() {
        this.populateDeviceSelect('patch-target-devices');
        this.openModal('patchModal');
    }

    openCustomMessageModal() {
        this.populateDeviceSelect('message-target-devices');
        this.openModal('customMessageModal');
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
            
            // Focus first input
            const firstInput = modal.querySelector('input, textarea, select');
            if (firstInput) {
                setTimeout(() => firstInput.focus(), 100);
            }
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }

    populateDeviceSelects() {
        const selects = ['code-target-devices', 'patch-target-devices', 'message-target-devices'];
        selects.forEach(selectId => this.populateDeviceSelect(selectId));
    }

    populateDeviceSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;

        select.innerHTML = this.devices.map(device => 
            `<option value="${device.deviceId}" ${this.selectedDevices.has(device.deviceId) ? 'selected' : ''}>
                ${device.deviceId} (${device.deviceType})
            </option>`
        ).join('');
    }

    // Advanced Operations
    async executeCode() {
        const targetDevices = Array.from(document.getElementById('code-target-devices').selectedOptions)
            .map(option => option.value);
        const language = document.getElementById('code-language').value;
        const code = document.getElementById('code-content').value.trim();

        if (targetDevices.length === 0) {
            this.showToast('Please select target devices', 'warning');
            return;
        }

        if (!code) {
            this.showToast('Please enter code to execute', 'warning');
            return;
        }

        try {
            this.showToast(`Executing ${language} code on ${targetDevices.length} devices...`, 'info');

            for (const deviceId of targetDevices) {
                const response = await fetch(`/api/devices/${deviceId}/code`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, language })
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const result = await response.json();
                this.addActivityLog(`Code executed on ${deviceId}: ${result.message}`, 'success');
            }

            this.showToast(`Code executed successfully on ${targetDevices.length} devices`, 'success');
            this.closeModal('codeModal');

            // Clear form
            document.getElementById('code-content').value = '';

        } catch (error) {
            console.error('Error executing code:', error);
            this.showToast('Failed to execute code: ' + error.message, 'error');
            this.addActivityLog('Code execution failed: ' + error.message, 'error');
        }
    }

    async deployPatch() {
        const targetDevices = Array.from(document.getElementById('patch-target-devices').selectedOptions)
            .map(option => option.value);
        const patchType = document.getElementById('patch-type').value;
        const version = document.getElementById('patch-version').value.trim();
        const description = document.getElementById('patch-description').value.trim();

        if (targetDevices.length === 0) {
            this.showToast('Please select target devices', 'warning');
            return;
        }

        if (!version) {
            this.showToast('Please enter patch version', 'warning');
            return;
        }

        try {
            this.showToast(`Deploying ${patchType} patch v${version} to ${targetDevices.length} devices...`, 'info');

            for (const deviceId of targetDevices) {
                const response = await fetch(`/api/devices/${deviceId}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        properties: {
                            patchType,
                            version,
                            description,
                            timestamp: new Date().toISOString()
                        }
                    })
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const result = await response.json();
                this.addActivityLog(`Patch deployed to ${deviceId}: ${patchType} v${version}`, 'success');
            }

            this.showToast(`Patch deployed successfully to ${targetDevices.length} devices`, 'success');
            this.closeModal('patchModal');

            // Clear form
            document.getElementById('patch-version').value = '';
            document.getElementById('patch-description').value = '';

        } catch (error) {
            console.error('Error deploying patch:', error);
            this.showToast('Failed to deploy patch: ' + error.message, 'error');
            this.addActivityLog('Patch deployment failed: ' + error.message, 'error');
        }
    }

    async sendCustomMessage() {
        const targetDevices = Array.from(document.getElementById('message-target-devices').selectedOptions)
            .map(option => option.value);
        const messageType = document.getElementById('message-type-select').value;
        const priority = document.getElementById('message-priority').value;
        const content = document.getElementById('message-content-text').value.trim();

        if (targetDevices.length === 0) {
            this.showToast('Please select target devices', 'warning');
            return;
        }

        if (!content) {
            this.showToast('Please enter message content', 'warning');
            return;
        }

        try {
            this.showToast(`Sending ${messageType} message to ${targetDevices.length} devices...`, 'info');

            const response = await fetch('/api/messages/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    deviceIds: targetDevices,
                    messageType,
                    content: {
                        message: content,
                        priority,
                        timestamp: new Date().toISOString()
                    }
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            this.addActivityLog(`Custom message sent to ${targetDevices.length} devices`, 'success');
            this.closeModal('customMessageModal');

            // Clear form
            document.getElementById('message-content-text').value = '';

        } catch (error) {
            console.error('Error sending message:', error);
            this.showToast('Failed to send message: ' + error.message, 'error');
            this.addActivityLog('Message sending failed: ' + error.message, 'error');
        }
    }

    async checkAllDeviceStatus() {
        const connectedDevices = this.devices.filter(d => d.status === 'Connected');
        
        if (connectedDevices.length === 0) {
            this.showToast('No connected devices to check', 'warning');
            return;
        }

        try {
            this.showToast(`Checking status of ${connectedDevices.length} devices...`, 'info');

            for (const device of connectedDevices) {
                const response = await fetch(`/api/devices/${device.deviceId}/status`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ checkType: 'health' })
                });

                if (response.ok) {
                    const result = await response.json();
                    this.addActivityLog(`Status check ${device.deviceId}: ${result.message}`, 'info');
                }
            }

            this.showToast('Device status checks completed', 'success');

        } catch (error) {
            console.error('Error checking device status:', error);
            this.showToast('Failed to check device status: ' + error.message, 'error');
        }
    }

    // View Management
    setView(viewType) {
        this.currentView = viewType;
        const container = document.getElementById('devices-container');
        
        // Update button states
        document.getElementById('grid-view').classList.toggle('active', viewType === 'grid');
        document.getElementById('list-view').classList.toggle('active', viewType === 'list');
        
        // Apply view
        container.className = viewType === 'grid' ? 'device-grid' : 'device-list';
        
        this.showToast(`Switched to ${viewType} view`, 'info');
    }

    // Activity Log Management
    addActivityLog(message, type = 'info') {
        const logContainer = document.getElementById('activity-log-content');
        if (!logContainer) return;

        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.innerHTML = `
            <div class="log-timestamp">${timestamp}</div>
            <div class="log-message">${message}</div>
        `;

        logContainer.insertBefore(logEntry, logContainer.firstChild);

        // Limit log entries
        while (logContainer.children.length > 50) {
            logContainer.removeChild(logContainer.lastChild);
        }

        // Auto-scroll to top for new entries
        logContainer.scrollTop = 0;
    }

    clearActivityLog() {
        const logContainer = document.getElementById('activity-log-content');
        if (logContainer) {
            logContainer.innerHTML = '';
            this.showToast('Activity log cleared', 'info');
        }
    }

    exportActivityLog() {
        const logEntries = Array.from(document.querySelectorAll('.log-entry')).map(entry => {
            const timestamp = entry.querySelector('.log-timestamp').textContent;
            const message = entry.querySelector('.log-message').textContent;
            return `${timestamp}: ${message}`;
        });

        const content = logEntries.join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `medical-iot-activity-log-${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast('Activity log exported', 'success');
    }

    // Toast Notifications - Enhanced
    showToast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if (!container) {
            console.error('Toast container not found');
            return;
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        const titles = {
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            info: 'Information'
        };

        toast.innerHTML = `
            <div class="toast-content">
                <i class="toast-icon ${icons[type] || icons.info}"></i>
                <div class="toast-message">
                    <div class="toast-title">${titles[type] || titles.info}</div>
                    <div class="toast-text">${message}</div>
                </div>
                <button class="toast-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        container.appendChild(toast);

        // Show toast with animation
        setTimeout(() => {
            toast.classList.add('show');
        }, 100);

        // Auto-remove toast
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 400);
            }
        }, duration);
    }

    showWelcomeToast() {
        this.showToast('Welcome to Medical IoT Dashboard! 🏥', 'success', 3000);
    }

    // Load security statistics
    async loadSecurityStats() {
        try {
            // Try to get blocked IPs count from API server (if accessible)
            const response = await fetch('/api/status');
            if (response.ok) {
                const data = await response.json();
                // Update blocked IPs count if available
                const blockedIPsElement = document.getElementById('blocked-ips-count');
                if (blockedIPsElement && data.security_stats) {
                    blockedIPsElement.textContent = `${data.security_stats.blocked_ips || 0} Blocked IPs`;
                }
            }
        } catch (error) {
            // Silently fail - API server might not be accessible
            console.log('Security stats not available:', error.message);
        }
    }

    // Auto-refresh
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            this.loadDevices();
            this.loadSecurityStats(); // Also refresh security stats
        }, 30000); // Refresh every 30 seconds
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    // Event Listeners
    setupEventListeners() {
        // Modal close on background click
        window.addEventListener('click', (event) => {
            if (event.target.classList.contains('modal')) {
                const modalId = event.target.id;
                this.closeModal(modalId);
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                // Close any open modals
                const openModal = document.querySelector('.modal[style*="display: block"]');
                if (openModal) {
                    this.closeModal(openModal.id);
                }
            }
        });

        // Handle page visibility change
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopAutoRefresh();
            } else {
                this.startAutoRefresh();
                this.loadDevices(); // Refresh when page becomes visible
            }
        });
    }

    // Individual Device Actions - New Enhanced Methods
    async sendCodeToDevice(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        if (device.status !== 'Connected') {
            this.showToast('Device must be connected to execute code', 'warning');
            return;
        }

        const code = prompt(`Enter Python code to execute on ${deviceId}:`, 'print("Hello from IoT device!")');
        if (!code) return;

        try {
            this.showToast(`Executing code on ${deviceId}...`, 'info');
            
            const response = await fetch(`/api/devices/${deviceId}/code`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    deviceId: deviceId,
                    code: code,
                    language: 'python',
                    parameters: {}
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(`Code executed on ${deviceId}: ${result.message}`, 'success');
            this.addActivityLog(`Code executed on ${deviceId}`, 'success');

        } catch (error) {
            console.error('Error executing code:', error);
            this.showToast(`Failed to execute code on ${deviceId}: ${error.message}`, 'error');
            this.addActivityLog(`Code execution failed on ${deviceId}: ${error.message}`, 'error');
        }
    }

    async sendPatchToDevice(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        if (device.status !== 'Connected') {
            this.showToast('Device must be connected to deploy patch', 'warning');
            return;
        }

        const patchVersion = prompt(`Enter patch version for ${deviceId}:`, 'v2.1.0');
        if (!patchVersion) return;

        try {
            this.showToast(`Deploying patch ${patchVersion} to ${deviceId}...`, 'info');
            
            const response = await fetch(`/api/devices/${deviceId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    deviceId: deviceId,
                    properties: {
                        softwareVersion: patchVersion,
                        patchType: 'firmware_update',
                        lastUpdate: new Date().toISOString()
                    }
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(`Patch deployed to ${deviceId}: ${result.message}`, 'success');
            this.addActivityLog(`Patch ${patchVersion} deployed to ${deviceId}`, 'success');
            await this.loadDevices(); // Refresh to show updated device info

        } catch (error) {
            console.error('Error deploying patch:', error);
            this.showToast(`Failed to deploy patch to ${deviceId}: ${error.message}`, 'error');
            this.addActivityLog(`Patch deployment failed on ${deviceId}: ${error.message}`, 'error');
        }
    }

    async checkDeviceStatus(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        try {
            this.showToast(`Checking health of ${deviceId}...`, 'info');
            
            const response = await fetch(`/api/devices/${deviceId}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    deviceId: deviceId,
                    statusType: 'all'
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            
            // Show detailed health status
            const healthStatus = result.health_status || 'Unknown';
            const batteryLevel = result.battery_level || 'N/A';
            const temperature = result.temperature || 'N/A';
            
            const healthMessage = `${deviceId} Health Check:\n` +
                                `Status: ${healthStatus}\n` +
                                `Battery: ${batteryLevel}%\n` +
                                `Temperature: ${temperature}°C`;
            
            alert(healthMessage);
            this.showToast(`Health check completed for ${deviceId}`, 'success');
            this.addActivityLog(`Health check: ${deviceId} status is ${healthStatus}`, 'info');

        } catch (error) {
            console.error('Error checking device status:', error);
            this.showToast(`Failed to check ${deviceId} status: ${error.message}`, 'error');
            this.addActivityLog(`Health check failed for ${deviceId}: ${error.message}`, 'error');
        }
    }

    async sendCustomMessage(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        if (device.status !== 'Connected') {
            this.showToast('Device must be connected to send message', 'warning');
            return;
        }

        const message = prompt(`Enter custom message for ${deviceId}:`, 'Hello from dashboard!');
        if (!message) return;

        try {
            this.showToast(`Sending message to ${deviceId}...`, 'info');
            
            const response = await fetch('/api/messages/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    deviceId: deviceId,
                    messageType: 'normal',
                    payload: { customMessage: message },
                    priority: 'normal',
                    timeout: 30
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(`Message sent to ${deviceId}: ${result.message}`, 'success');
            this.addActivityLog(`Custom message sent to ${deviceId}`, 'success');

        } catch (error) {
            console.error('Error sending message:', error);
            this.showToast(`Failed to send message to ${deviceId}: ${error.message}`, 'error');
            this.addActivityLog(`Message send failed to ${deviceId}: ${error.message}`, 'error');
        }
    }

    async restartDevice(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        if (device.status !== 'Connected') {
            this.showToast('Device must be connected to restart', 'warning');
            return;
        }

        if (!confirm(`Are you sure you want to restart ${deviceId}? This may temporarily interrupt its operations.`)) {
            return;
        }

        try {
            this.showToast(`Restarting ${deviceId}...`, 'info');
            
            const response = await fetch(`/api/devices/${deviceId}/code`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    deviceId: deviceId,
                    code: 'import os; os.system("shutdown /r /t 0")',  // Windows restart command
                    language: 'python',
                    parameters: { operation: 'restart' }
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            this.showToast(`Restart command sent to ${deviceId}`, 'warning');
            this.addActivityLog(`Restart command sent to ${deviceId}`, 'warning');
            
            // Device might disconnect after restart
            setTimeout(() => {
                this.loadDevices();
            }, 5000);

        } catch (error) {
            console.error('Error restarting device:', error);
            this.showToast(`Failed to restart ${deviceId}: ${error.message}`, 'error');
            this.addActivityLog(`Restart failed for ${deviceId}: ${error.message}`, 'error');
        }
    }

    async openDeviceDetails(deviceId) {
        const device = this.devices.find(d => d.deviceId === deviceId);
        if (!device) {
            this.showToast('Device not found', 'error');
            return;
        }

        // Create and show device details modal
        const modalHtml = `
            <div class="modal-header">
                <h2><i class="fas fa-info-circle"></i> Device Details: ${device.deviceId}</h2>
                <button class="close-btn" onclick="dashboard.closeModal('device-details-modal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="device-detail-grid">
                    <div class="detail-group">
                        <h3>Basic Information</h3>
                        <div class="detail-item">
                            <span class="label">Device ID:</span>
                            <span class="value">${device.deviceId}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Device Type:</span>
                            <span class="value">${device.deviceType}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Manufacturer:</span>
                            <span class="value">${device.manufacturer}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Status:</span>
                            <span class="value status-${device.status.toLowerCase()}">${device.status}</span>
                        </div>
                    </div>
                    
                    <div class="detail-group">
                        <h3>System Information</h3>
                        <div class="detail-item">
                            <span class="label">Operating System:</span>
                            <span class="value">${device.osName} ${device.osVersion}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Software Version:</span>
                            <span class="value">${device.softwareVersion}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Runtime:</span>
                            <span class="value">${device.runtime}</span>
                        </div>
                    </div>
                    
                    <div class="detail-group">
                        <h3>Connection Information</h3>
                        <div class="detail-item">
                            <span class="label">Connection String:</span>
                            <span class="value" style="font-family: monospace; font-size: 0.8em; word-break: break-all;">
                                ${device.connectionString ? device.connectionString.substring(0, 50) + '...' : 'Not available'}
                            </span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Last Activity:</span>
                            <span class="value">${new Date().toLocaleString()}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        const existingModal = document.getElementById('device-details-modal');
        if (existingModal) {
            existingModal.remove();
        }

        const modal = document.createElement('div');
        modal.id = 'device-details-modal';
        modal.className = 'modal';
        modal.innerHTML = `<div class="modal-content">${modalHtml}</div>`;
        
        document.body.appendChild(modal);
        modal.style.display = 'block';
        
        this.addActivityLog(`Viewed details for ${deviceId}`, 'info');
    }

    // Public methods for global access
    async refreshDevices() {
        await this.loadDevices();
        this.showToast('Devices refreshed', 'success');
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new MedicalIoTDashboard();
});

// Global functions for backward compatibility
function refreshDevices() {
    if (window.dashboard) {
        window.dashboard.refreshDevices();
    }
}

function connectAllDevices() {
    if (window.dashboard) {
        window.dashboard.connectAllDevices();
    }
}

function disconnectAllDevices() {
    if (window.dashboard) {
        window.dashboard.disconnectAllDevices();
    }
}

function sendTelemetryBatch() {
    if (window.dashboard) {
        window.dashboard.sendTelemetryBatch();
    }
}

function startContinuousTelemetry() {
    if (window.dashboard) {
        window.dashboard.startContinuousTelemetry();
    }
}

function openBulkCodeModal() {
    if (window.dashboard) {
        window.dashboard.openBulkCodeModal();
    }
}

function openBulkPatchModal() {
    if (window.dashboard) {
        window.dashboard.openBulkPatchModal();
    }
}

function openCustomMessageModal() {
    if (window.dashboard) {
        window.dashboard.openCustomMessageModal();
    }
}

function checkAllDeviceStatus() {
    if (window.dashboard) {
        window.dashboard.checkAllDeviceStatus();
    }
}

function executeCode() {
    if (window.dashboard) {
        window.dashboard.executeCode();
    }
}

function deployPatch() {
    if (window.dashboard) {
        window.dashboard.deployPatch();
    }
}

function sendCustomMessage() {
    if (window.dashboard) {
        window.dashboard.sendCustomMessage();
    }
}

function closeModal(modalId) {
    if (window.dashboard) {
        window.dashboard.closeModal(modalId);
    }
}

function setView(viewType) {
    if (window.dashboard) {
        window.dashboard.setView(viewType);
    }
}

function clearActivityLog() {
    if (window.dashboard) {
        window.dashboard.clearActivityLog();
    }
}

function exportActivityLog() {
    if (window.dashboard) {
        window.dashboard.exportActivityLog();
    }
}

function viewSystemLogs() {
    window.open('/admin/ids', '_blank');
}