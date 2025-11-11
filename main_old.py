from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
import logging
from pathlib import Path
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API Server configuration
API_SERVER_URL = "http://localhost:8001"

# Create FastAPI web server app
app = FastAPI(
    title="Medical IoT Web Interface",
    description="Web interface for managing medical IoT devices - communicates with API server",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Helper functions
def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def proxy_to_api_server(request: Request, endpoint: str, method: str = "GET", body: bytes = None):
    """Proxy requests to the API server"""
    user_ip = get_client_ip(request)
    api_url = f"{API_SERVER_URL}{endpoint}"
    
    headers = {
        "X-Forwarded-For": user_ip,
        "X-Real-IP": user_ip,
        "Content-Type": request.headers.get("Content-Type", "application/json")
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if method.upper() == "GET":
                response = await client.get(api_url, headers=headers)
            elif method.upper() == "POST":
                response = await client.post(api_url, content=body, headers=headers)
            elif method.upper() == "PATCH":
                response = await client.patch(api_url, content=body, headers=headers)
            elif method.upper() == "DELETE":
                response = await client.delete(api_url, headers=headers)
            else:
                return JSONResponse({"error": "Method not supported"}, status_code=405)
            
            return JSONResponse(
                content=response.json() if response.content else {},
                status_code=response.status_code
            )
    except httpx.RequestError as e:
        logger.error(f"Error proxying to API server: {e}")
        return JSONResponse(
            {"error": "API server unavailable", "details": str(e)},
            status_code=503
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return JSONResponse(
            {"error": "Internal server error", "details": str(e)},
            status_code=500
        )

# Web Interface Endpoints

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main web interface"""
    html_file = Path("static/index.html")
    if html_file.exists():
        return HTMLResponse(content=html_file.read_text(), status_code=200)
    return HTMLResponse(content="""
    <html>
        <head><title>Medical IoT Device Manager</title></head>
        <body>
            <h1>Medical IoT Device Management Web Interface</h1>
            <p>Web interface is running. API server should be running on port 8001.</p>
            <p>Visit <a href="/docs">/docs</a> for web server documentation.</p>
        </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Health check for web server"""
    return {"status": "healthy", "service": "web-server", "api_server": API_SERVER_URL}

# API Proxy Endpoints
@app.get("/api/devices")
async def get_devices(request: Request, client: TelemetryClient = Depends(get_telemetry_client)):
    """Get all registered devices"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/devices", user_ip, "Fetching all devices")
    
    devices = []
    for device in client.devices:
        # Check if device is connected
        status = "Connected" if device['deviceId'] in client.clients else "Disconnected"
        
        devices.append(DeviceInfo(
            deviceId=device['deviceId'],
            deviceType=device['deviceType'],
            manufacturer=device['manufacturer'],
            osName=device['osName'],
            osVersion=device['osVersion'],
            connectionString=device['connectionString'],
            status=status
        ))
    
    return devices

@app.get("/api/devices/{device_id}", response_model=DeviceInfo)
async def get_device(device_id: str, request: Request, client: TelemetryClient = Depends(get_telemetry_client)):
    """Get specific device information"""
    user_ip = get_client_ip(request)
    log_request(request, f"/api/devices/{device_id}", user_ip, f"Fetching device: {device_id}")
    
    device = next((d for d in client.devices if d['deviceId'] == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    status = "Connected" if device_id in client.clients else "Disconnected"
    
    return DeviceInfo(
        deviceId=device['deviceId'],
        deviceType=device['deviceType'],
        manufacturer=device['manufacturer'],
        osName=device['osName'],
        osVersion=device['osVersion'],
        connectionString=device['connectionString'],
        status=status
    )

@app.post("/api/devices/connect", response_model=APIResponse)
async def connect_devices(
    request_data: DeviceConnectionRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Connect to specified devices"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/devices/connect", user_ip, f"Connecting devices: {request_data.deviceIds}")
    
    try:
        await client.connect_devices(request_data.deviceIds)
        connected_count = len([d for d in request_data.deviceIds if d in client.clients])
        
        return APIResponse(
            success=True,
            message=f"Connected {connected_count}/{len(request_data.deviceIds)} devices",
            data={"connected_devices": list(client.clients.keys())}
        )
    except Exception as e:
        logger.error(f"Error connecting devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/disconnect", response_model=APIResponse)
async def disconnect_devices(
    request_data: DeviceConnectionRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Disconnect specified devices"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/devices/disconnect", user_ip, f"Disconnecting devices: {request_data.deviceIds}")
    
    try:
        disconnected = []
        for device_id in request_data.deviceIds:
            if device_id in client.clients:
                await client.clients[device_id].disconnect()
                del client.clients[device_id]
                disconnected.append(device_id)
        
        return APIResponse(
            success=True,
            message=f"Disconnected {len(disconnected)} devices",
            data={"disconnected_devices": disconnected}
        )
    except Exception as e:
        logger.error(f"Error disconnecting devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/telemetry/send", response_model=APIResponse)
async def send_telemetry(
    request_data: TelemetryRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Send telemetry messages from devices"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/telemetry/send", user_ip, 
                f"Sending telemetry - Devices: {request_data.deviceIds}, Count: {request_data.messageCount}")
    
    try:
        # Connect to devices if needed
        if request_data.deviceIds:
            await client.connect_devices(request_data.deviceIds)
        else:
            # Connect to all devices
            await client.connect_devices()
        
        if not client.clients:
            raise HTTPException(status_code=400, detail="No devices connected")
        
        # Send telemetry
        await client.send_telemetry_batch(request_data.messageCount)
        
        total_messages = request_data.messageCount * len(client.clients)
        return APIResponse(
            success=True,
            message=f"Sent {total_messages} telemetry messages from {len(client.clients)} devices",
            data={
                "devices": list(client.clients.keys()),
                "messages_per_device": request_data.messageCount,
                "total_messages": total_messages
            }
        )
    except Exception as e:
        logger.error(f"Error sending telemetry: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/telemetry/continuous", response_model=APIResponse)
async def start_continuous_telemetry(
    request_data: TelemetryRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Start continuous telemetry sending"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/telemetry/continuous", user_ip, 
                f"Starting continuous telemetry - Interval: {request_data.interval}s, Duration: {request_data.duration}s")
    
    if not request_data.interval:
        raise HTTPException(status_code=400, detail="Interval is required for continuous mode")
    
    try:
        # Connect to devices if needed
        if request_data.deviceIds:
            await client.connect_devices(request_data.deviceIds)
        else:
            await client.connect_devices()
        
        if not client.clients:
            raise HTTPException(status_code=400, detail="No devices connected")
        
        # Start continuous telemetry in background
        background_tasks.add_task(
            client.run_continuous,
            request_data.interval,
            request_data.duration
        )
        
        return APIResponse(
            success=True,
            message=f"Started continuous telemetry for {len(client.clients)} devices",
            data={
                "devices": list(client.clients.keys()),
                "interval": request_data.interval,
                "duration": request_data.duration
            }
        )
    except Exception as e:
        logger.error(f"Error starting continuous telemetry: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/telemetry/sample/{device_type}")
async def get_sample_telemetry(device_type: str, request: Request):
    """Get sample telemetry data for a device type"""
    user_ip = get_client_ip(request)
    log_request(request, f"/api/telemetry/sample/{device_type}", user_ip, f"Getting sample data for: {device_type}")
    
    generator = MedicalDataGenerator()
    sample_data = generator.generate_data(device_type)
    
    if "error" in sample_data:
        raise HTTPException(status_code=400, detail=sample_data["error"])
    
    return APIResponse(
        success=True,
        message=f"Sample telemetry data for {device_type}",
        data=sample_data
    )

@app.patch("/api/devices/{device_id}", response_model=APIResponse)
async def update_device(
    device_id: str,
    request_data: DeviceUpdateRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Update device properties (placeholder for twin updates)"""
    user_ip = get_client_ip(request)
    log_request(request, f"/api/devices/{device_id}", user_ip, f"Updating device properties: {request_data.properties}")
    
    # Find device
    device = next((d for d in client.devices if d['deviceId'] == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    # This is a placeholder - in a real implementation, you would update the device twin
    return APIResponse(
        success=True,
        message=f"Device {device_id} properties updated",
        data={"device_id": device_id, "updated_properties": request_data.properties}
    )

@app.post("/api/messages/send", response_model=APIResponse)
async def send_custom_message(
    request_data: MessageRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Send custom message to device based on message type"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/messages/send", user_ip, 
                f"Sending {request_data.messageType} message to {request_data.deviceId}")
    
    device = next((d for d in client.devices if d['deviceId'] == request_data.deviceId), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {request_data.deviceId} not found")
    
    # Format message based on type
    message_data = {
        "messageType": request_data.messageType,
        "deviceId": request_data.deviceId,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "priority": request_data.priority,
        "userIP": user_ip,
        "payload": request_data.payload
    }
    
    if request_data.messageType == "normal":
        # Generate telemetry data
        generator = MedicalDataGenerator()
        telemetry_data = generator.generate_data(device['deviceType'])
        message_data["telemetryData"] = telemetry_data
        message_data["description"] = "Normal telemetry data request"
    
    elif request_data.messageType == "status":
        message_data["statusCheck"] = {
            "requestedStatus": request_data.payload.get("statusType", "health"),
            "includeMetrics": request_data.payload.get("includeMetrics", True),
            "includeLogs": request_data.payload.get("includeLogs", False)
        }
        message_data["description"] = "Device status check request"
    
    elif request_data.messageType == "update":
        message_data["updateRequest"] = {
            "properties": request_data.payload.get("properties", {}),
            "configuration": request_data.payload.get("configuration", {}),
            "firmware": request_data.payload.get("firmware", None)
        }
        message_data["description"] = "Device update request"
    
    elif request_data.messageType == "patch":
        message_data["patchRequest"] = {
            "patchData": request_data.payload.get("patchData", {}),
            "patchType": request_data.payload.get("patchType", "configuration"),
            "rollbackEnabled": request_data.payload.get("rollbackEnabled", True)
        }
        message_data["description"] = "Device patch request"
    
    elif request_data.messageType == "code":
        message_data["codeExecution"] = {
            "code": request_data.payload.get("code", ""),
            "language": request_data.payload.get("language", "python"),
            "parameters": request_data.payload.get("parameters", {}),
            "timeout": request_data.timeout
        }
        message_data["description"] = "Code execution request"
    
    try:
        # Connect to device if needed
        if request_data.deviceId not in client.clients:
            await client.connect_devices([request_data.deviceId])
        
        if request_data.deviceId in client.clients:
            # Send the formatted message
            from azure.iot.device import Message
            message = Message(json.dumps(message_data))
            message.content_encoding = "utf-8"
            message.content_type = "application/json"
            message.custom_properties["messageType"] = request_data.messageType
            message.custom_properties["priority"] = request_data.priority
            message.custom_properties["userIP"] = user_ip
            
            await client.clients[request_data.deviceId].send_message(message)
            
            return APIResponse(
                success=True,
                message=f"{request_data.messageType.title()} message sent to {request_data.deviceId}",
                data={
                    "messageId": f"msg_{int(time.time())}",
                    "deviceId": request_data.deviceId,
                    "messageType": request_data.messageType,
                    "payload": message_data
                }
            )
        else:
            raise HTTPException(status_code=400, detail=f"Could not connect to device {request_data.deviceId}")
    
    except Exception as e:
        logger.error(f"Error sending message to {request_data.deviceId}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/{device_id}/status", response_model=APIResponse)
async def check_device_status(
    device_id: str,
    request_data: StatusRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Check specific device status"""
    user_ip = get_client_ip(request)
    log_request(request, f"/api/devices/{device_id}/status", user_ip, 
                f"Checking {request_data.statusType} status")
    
    device = next((d for d in client.devices if d['deviceId'] == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    # Simulate status check
    status_data = {
        "deviceId": device_id,
        "statusType": request_data.statusType,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "userIP": user_ip
    }
    
    if request_data.statusType == "health":
        status_data["health"] = {
            "overall": "Good",
            "battery": random.randint(75, 100),
            "temperature": round(random.uniform(20, 25), 1),
            "lastMaintenance": "2025-09-15T10:00:00Z"
        }
    elif request_data.statusType == "connectivity":
        status_data["connectivity"] = {
            "status": "Connected" if device_id in client.clients else "Disconnected",
            "signalStrength": random.randint(70, 100),
            "lastSeen": datetime.now(timezone.utc).isoformat(),
            "networkType": "WiFi"
        }
    elif request_data.statusType == "sensors":
        status_data["sensors"] = {
            "active": random.randint(3, 8),
            "total": 8,
            "calibrated": True,
            "lastCalibration": "2025-09-18T08:00:00Z"
        }
    else:
        status_data["allStatus"] = {
            "health": "Good",
            "connectivity": "Connected" if device_id in client.clients else "Disconnected",
            "sensors": "Active",
            "battery": random.randint(75, 100)
        }
    
    return APIResponse(
        success=True,
        message=f"Status check completed for {device_id}",
        data=status_data
    )

@app.post("/api/devices/{device_id}/code", response_model=APIResponse)
async def execute_code_on_device(
    device_id: str,
    request_data: CodeRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Execute code on device (simulated)"""
    user_ip = get_client_ip(request)
    log_request(request, f"/api/devices/{device_id}/code", user_ip, 
                f"Executing {request_data.language} code")
    
    device = next((d for d in client.devices if d['deviceId'] == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    # Simulate code execution
    execution_result = {
        "deviceId": device_id,
        "executionId": f"exec_{int(time.time())}",
        "language": request_data.language,
        "code": request_data.code,
        "parameters": request_data.parameters,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "userIP": user_ip,
        "status": "completed",
        "output": f"Code executed successfully on {device['deviceType']}",
        "executionTime": round(random.uniform(0.1, 2.0), 2)
    }
    
    return APIResponse(
        success=True,
        message=f"Code executed on {device_id}",
        data=execution_result
    )

@app.get("/api/status", response_model=APIResponse)
async def get_system_status(request: Request, client: TelemetryClient = Depends(get_telemetry_client)):
    """Get system status and statistics"""
    user_ip = get_client_ip(request)
    log_request(request, "/api/status", user_ip, "Getting system status")
    
    connected_devices = len(client.clients)
    total_devices = len(client.devices)
    
    device_types = {}
    for device in client.devices:
        device_type = device['deviceType']
        device_types[device_type] = device_types.get(device_type, 0) + 1
    
    return APIResponse(
        success=True,
        message="System status retrieved",
        data={
            "connected_devices": connected_devices,
            "total_devices": total_devices,
            "connection_rate": round(connected_devices / total_devices * 100, 1) if total_devices > 0 else 0,
            "device_types": device_types,
            "uptime": "System running"
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )