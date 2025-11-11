from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import json
import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path
import uvicorn
from contextlib import asynccontextmanager
import httpx
# Import our existing modules
from telemetry_client import TelemetryClient, MedicalDataGenerator

# Import IDS components
from ids_middleware import IDSMiddleware, SecurityHeaders
from professional_admin_dashboard import admin_router

# Import AI agent components
from ai_integration_api import ai_router
from ai_security_client import ai_security_client

# Import CVE management system
from cve_management_system import get_cve_manager
from osv_cve_fetcher import OSVFetcher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global telemetry client
telemetry_client: Optional[TelemetryClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global telemetry_client
    try:
        # Initialize telemetry client
        telemetry_client = TelemetryClient()
        telemetry_client.load_devices()
        logger.info(f"API Server: Loaded {len(telemetry_client.devices)} devices")
        yield
    finally:
        # Cleanup
        if telemetry_client and telemetry_client.clients:
            await telemetry_client.disconnect_all()
        logger.info("API Server shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="Medical IoT Device API Server",
    description="Dedicated REST API server for managing medical IoT devices and telemetry data",
    version="1.0.0",
    lifespan=lifespan
)

# AI Security is now handled via HTTP calls to separate service on port 8002

# Add IDS middleware for security monitoring
app.add_middleware(IDSMiddleware)

# Enable CORS for web server communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000", 
        "http://127.0.0.1:8000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://localhost:8003",  # Dashboard server
        "http://127.0.0.1:8003",  # Dashboard server
        "http://localhost:8004",  # Dashboard server (alt port)
        "http://127.0.0.1:8004",  # Dashboard server (alt port)
        "http://localhost",
        "http://127.0.0.1"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include admin dashboard router
app.include_router(admin_router)

# Include AI agent router
app.include_router(ai_router, prefix="/api")

# Pydantic models
class DeviceInfo(BaseModel):
    deviceId: str
    deviceType: str
    manufacturer: str
    osName: str
    osVersion: str
    connectionString: str
    status: str = "Unknown"

class TelemetryMessage(BaseModel):
    deviceId: str
    data: Dict[str, Any]
    timestamp: Optional[str] = None

class TelemetryRequest(BaseModel):
    deviceIds: Optional[List[str]] = None
    messageCount: int = Field(default=1, ge=1, le=100)
    interval: Optional[float] = Field(default=None, ge=0.1)
    duration: Optional[float] = Field(default=None, ge=1)

class DeviceConnectionRequest(BaseModel):
    deviceIds: List[str]

class DeviceUpdateRequest(BaseModel):
    deviceId: str
    properties: Dict[str, Any]

class MessageRequest(BaseModel):
    deviceId: str
    messageType: str = Field(..., pattern="^(normal|status|update|patch|code)$")
    payload: Dict[str, Any] = {}
    priority: str = Field(default="normal", pattern="^(low|normal|high|critical)$")
    timeout: Optional[int] = Field(default=30, ge=1, le=300)

class CodeRequest(BaseModel):
    deviceId: str
    code: str
    language: str = Field(default="python", pattern="^(python|javascript|shell)$")
    parameters: Dict[str, Any] = {}

class StatusRequest(BaseModel):
    deviceId: str
    statusType: str = Field(default="health", pattern="^(health|connectivity|battery|sensors|all)$")

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# Helper functions
def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"

def log_api_request(request: Request, endpoint: str, user_ip: str, details: str = ""):
    """Log API request with user IP and details"""
    logger.info(f"API Request - IP: {user_ip} | Endpoint: {endpoint} | Method: {request.method} | Details: {details}")

async def get_telemetry_client() -> TelemetryClient:
    """Dependency to get telemetry client"""
    if not telemetry_client:
        raise HTTPException(status_code=500, detail="Telemetry client not initialized")
    return telemetry_client

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "api-server", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/devices", response_model=List[DeviceInfo])
async def get_devices(request: Request, client: TelemetryClient = Depends(get_telemetry_client)):
    """Get all registered devices"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/devices", user_ip, "Fetching all devices")
    
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
    log_api_request(request, f"/api/devices/{device_id}", user_ip, f"Fetching device: {device_id}")
    
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
    log_api_request(request, "/api/devices/connect", user_ip, f"Connecting devices: {request_data.deviceIds}")
    
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
    log_api_request(request, "/api/devices/disconnect", user_ip, f"Disconnecting devices: {request_data.deviceIds}")
    
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
    log_api_request(request, "/api/telemetry/send", user_ip, 
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
    log_api_request(request, "/api/telemetry/continuous", user_ip, 
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
    log_api_request(request, f"/api/telemetry/sample/{device_type}", user_ip, f"Getting sample data for: {device_type}")
    
    generator = MedicalDataGenerator()
    sample_data = generator.generate_data(device_type)
    
    if "error" in sample_data:
        raise HTTPException(status_code=400, detail=sample_data["error"])
    
    return APIResponse(
        success=True,
        message=f"Sample telemetry data for {device_type}",
        data=sample_data
    )

@app.post("/api/messages/send", response_model=APIResponse)
async def send_custom_message(
    request_data: MessageRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Send custom message to device based on message type"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/messages/send", user_ip, 
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
    log_api_request(request, f"/api/devices/{device_id}/status", user_ip, 
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
    """Execute code on device (simulated) - AI Security Protected"""
    user_ip = get_client_ip(request)
    log_api_request(request, f"/api/devices/{device_id}/code", user_ip, 
                f"Executing {request_data.language} code")
    
    # AI Security Analysis - ALWAYS analyze code execution requests
    logger.info(f"🤖 Running AI security analysis for code execution request from {user_ip}")
    
    ai_analysis = ai_security_client.analyze_request(
        method="POST",
        path=f"/api/devices/{device_id}/code",
        headers=dict(request.headers),
        body=request_data.dict(),
        client_ip=user_ip
    )
    
    # Block request if AI determines it's malicious
    if not ai_analysis.get('approved', False):
        logger.warning(f"🚫 AI BLOCKED malicious code execution: {ai_analysis.get('reasons', [])}")
        raise HTTPException(
            status_code=403, 
            detail={
                "error": "Request blocked by AI security",
                "risk_score": ai_analysis.get('risk_score', 0),
                "reasons": ai_analysis.get('reasons', []),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    logger.info(f"✅ AI APPROVED code execution - Risk score: {ai_analysis.get('risk_score', 0)}")
    
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

@app.patch("/api/devices/{device_id}", response_model=APIResponse)
async def update_device(
    device_id: str,
    request_data: DeviceUpdateRequest,
    request: Request,
    client: TelemetryClient = Depends(get_telemetry_client)
):
    """Update device properties and handle patch deployments - AI Security Protected"""
    user_ip = get_client_ip(request)
    log_api_request(request, f"/api/devices/{device_id}", user_ip, f"Updating device properties: {request_data.properties}")
    
    # AI Security Analysis for device updates
    logger.info(f"🤖 Running AI security analysis for device update from {user_ip}")
    
    ai_analysis = ai_security_client.analyze_request(
        method="PATCH",
        path=f"/api/devices/{device_id}",
        headers=dict(request.headers),
        body=request_data.dict(),
        client_ip=user_ip
    )
    
    # Block request if AI determines it's malicious
    if not ai_analysis.get('approved', False):
        logger.warning(f"🚫 AI BLOCKED malicious device update: {ai_analysis.get('reasons', [])}")
        raise HTTPException(
            status_code=403, 
            detail={
                "error": "Request blocked by AI security",
                "risk_score": ai_analysis.get('risk_score', 0),
                "reasons": ai_analysis.get('reasons', []),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    logger.info(f"✅ AI APPROVED device update - Risk score: {ai_analysis.get('risk_score', 0)}")
    
    # Find device
    device = next((d for d in client.devices if d['deviceId'] == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    # Check if device is connected for certain operations
    is_patch_deployment = request_data.properties.get('patchType') == 'firmware_update'
    if is_patch_deployment and device_id not in client.clients:
        raise HTTPException(
            status_code=400, 
            detail=f"Device {device_id} must be connected for patch deployment"
        )
    
    # Update local device data
    properties = request_data.properties
    
    # Handle software version updates
    if 'softwareVersion' in properties:
        device['softwareVersion'] = properties['softwareVersion']
        
    # Handle patch deployment
    if is_patch_deployment:
        patch_version = properties.get('softwareVersion', 'unknown')
        
        # Simulate patch deployment process
        await asyncio.sleep(0.5)  # Simulate deployment time
        
        # Update device twin metadata
        if device_id in client.clients:
            device_client = client.clients[device_id]
            twin = await device_client.get_twin()
            if twin:
                # Update twin with new patch info
                patch_data = {
                    'patchVersion': patch_version,
                    'patchDeployedAt': datetime.now(timezone.utc).isoformat(),
                    'patchStatus': 'deployed',
                    'lastUpdate': properties.get('lastUpdate', datetime.now(timezone.utc).isoformat())
                }
                await device_client.patch_twin_reported_properties(patch_data)
        
        return APIResponse(
            success=True,
            message=f"Patch {patch_version} successfully deployed to {device_id}",
            data={
                "device_id": device_id, 
                "patch_version": patch_version,
                "deployment_status": "success",
                "updated_properties": properties
            }
        )
    
    # Handle other property updates
    return APIResponse(
        success=True,
        message=f"Device {device_id} properties updated successfully",
        data={"device_id": device_id, "updated_properties": properties}
    )

@app.get("/api/status", response_model=APIResponse)
async def get_system_status(request: Request, client: TelemetryClient = Depends(get_telemetry_client)):
    """Get system status and statistics"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/status", user_ip, "Getting system status")
    
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
            "uptime": "API Server running"
        }
    )

# CVE Management Endpoints
@app.get("/api/cve/dashboard")
async def get_cve_dashboard(request: Request):
    """Get CVE dashboard data with ML-based recommendations"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/cve/dashboard", user_ip, "Getting CVE dashboard data")
    
    try:
        cve_manager = await get_cve_manager()
        dashboard_data = await cve_manager.get_cve_dashboard_data()
        
        return {
            "success": True,
            "message": "CVE dashboard data retrieved successfully",
            "data": dashboard_data,
            **dashboard_data
        }
    except Exception as e:
        logger.error(f"Failed to get CVE dashboard data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVE data: {str(e)}")

@app.get("/api/cve/list")
async def get_cve_list(request: Request, severity: Optional[str] = None):
    """Get list of CVEs with optional severity filter"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/cve/list", user_ip, f"Getting CVE list (severity: {severity})")
    
    try:
        cve_manager = await get_cve_manager()
        cves = cve_manager.db.get_active_cves(severity_filter=severity)
        
        return APIResponse(
            success=True,
            message=f"Retrieved {len(cves)} CVEs",
            data={"cves": cves, "count": len(cves)}
        )
    except Exception as e:
        logger.error(f"Failed to get CVE list: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVE list: {str(e)}")

@app.post("/api/cve/{cve_id}/approve-update")
async def approve_cve_update(cve_id: str, request: Request):
    """Approve ML-recommended CVE update for a device"""
    user_ip = get_client_ip(request)
    
    # Get device_id from query params or request body
    device_id = request.query_params.get('device_id')
    if not device_id:
        try:
            body = await request.json()
            device_id = body.get('device_id')
        except:
            device_id = "unknown"
    
    log_api_request(request, f"/api/cve/{cve_id}/approve-update", user_ip, f"Approving update for {device_id}")
    
    try:
        # Here you would implement the actual update approval logic
        # For now, we'll simulate the approval
        
        logger.info(f"CVE update approved: {cve_id} for device {device_id}")
        
        return APIResponse(
            success=True,
            message=f"Update approved for CVE {cve_id} on device {device_id}",
            data={
                "cve_id": cve_id,
                "device_id": device_id,
                "status": "approved",
                "timestamp": datetime.now().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Failed to approve CVE update: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to approve update: {str(e)}")

@app.post("/api/cve/{cve_id}/reschedule-update")
async def reschedule_cve_update(cve_id: str, request: Request):
    """Reschedule CVE update to a new time"""
    user_ip = get_client_ip(request)
    
    # Get parameters from request body
    try:
        body = await request.json()
        device_id = body.get('device_id', 'unknown')
        new_time = body.get('new_time', datetime.now().isoformat())
    except:
        raise HTTPException(status_code=400, detail="Invalid request body")
    
    log_api_request(request, f"/api/cve/{cve_id}/reschedule-update", user_ip, f"Rescheduling update for {device_id}")
    
    try:
        # Here you would implement the actual rescheduling logic
        # For now, we'll simulate the rescheduling
        
        logger.info(f"CVE update rescheduled: {cve_id} for device {device_id} to {new_time}")
        
        return APIResponse(
            success=True,
            message=f"Update rescheduled for CVE {cve_id} on device {device_id}",
            data={
                "cve_id": cve_id,
                "device_id": device_id,
                "new_scheduled_time": new_time,
                "status": "rescheduled",
                "timestamp": datetime.now().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Failed to reschedule CVE update: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reschedule update: {str(e)}")

@app.post("/api/cve/refresh")
async def refresh_cve_data(request: Request):
    """Refresh CVE data from OSV (Open Source Vulnerabilities) database"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/cve/refresh", user_ip, "Refreshing CVE data from OSV")
    
    try:
        logger.info("Starting OSV CVE data refresh...")
        
        async with OSVFetcher() as fetcher:
            # Fetch medical IoT vulnerabilities
            osv_vulns = await fetcher.query_medical_iot_vulnerabilities()
            
            if not osv_vulns:
                return APIResponse(
                    success=False,
                    message="No vulnerabilities found from OSV",
                    data={"count": 0}
                )
            
            # Convert OSV data to our CVE format
            cve_manager = await get_cve_manager()
            converted_count = 0
            critical_count = 0
            
            for osv_vuln in osv_vulns:
                try:
                    # Get CVE ID from aliases if available
                    cve_id = None
                    for alias in osv_vuln.aliases:
                        if alias.startswith('CVE-'):
                            cve_id = alias
                            break
                    
                    if not cve_id:
                        cve_id = f"OSV-{osv_vuln.id}"
                    
                    # Map severity based on content analysis
                    severity_score = 5.0
                    severity_level = "MEDIUM"
                    
                    # Analyze description for severity keywords
                    desc_lower = (osv_vuln.summary + " " + osv_vuln.details).lower()
                    if any(word in desc_lower for word in ["critical", "remote code execution", "rce", "arbitrary code"]):
                        severity_score = 9.0
                        severity_level = "CRITICAL"
                        critical_count += 1
                    elif any(word in desc_lower for word in ["high", "privilege escalation", "sql injection"]):
                        severity_score = 7.0
                        severity_level = "HIGH"
                    elif any(word in desc_lower for word in ["low", "information disclosure"]):
                        severity_score = 3.0
                        severity_level = "LOW"
                    
                    # Create CVE entry
                    from cve_management_system import CVEEntry
                    cve_entry = CVEEntry(
                        cve_id=cve_id,
                        published_date=osv_vuln.published or datetime.now().isoformat(),
                        modified_date=osv_vuln.modified or datetime.now().isoformat(),
                        description=osv_vuln.summary or osv_vuln.details or "No description available",
                        severity_score=severity_score,
                        severity_level=severity_level,
                        affected_systems=osv_vuln.affected_packages or ["Unknown System"],
                        attack_vector="NETWORK",
                        exploit_available="exploit" in desc_lower,
                        patch_available="patch" in desc_lower or "fixed" in desc_lower,
                        patch_complexity="MEDIUM",
                        business_impact=severity_level,
                        affected_devices=["med-ecg-001", "med-pump-002", "med-monitor-003"]
                    )
                    
                    # Store in database
                    cve_manager.db.store_cve(cve_entry)
                    converted_count += 1
                    
                except Exception as e:
                    logger.error(f"Error converting OSV vulnerability {osv_vuln.id}: {e}")
                    continue
        
        return APIResponse(
            success=True,
            message=f"CVE data refreshed from OSV - {converted_count} vulnerabilities processed",
            data={
                "refresh_timestamp": datetime.now().isoformat(),
                "total_cves": converted_count,
                "critical_cves": critical_count,
                "source": "OSV (Open Source Vulnerabilities)"
            }
        )
    except Exception as e:
        logger.error(f"Failed to refresh CVE data from OSV: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to refresh CVE data: {str(e)}")

@app.post("/api/cve/refresh-data")
async def refresh_cve_data(request: Request):
    """Refresh CVE data from trusted sources like NIST NVD"""
    user_ip = get_client_ip(request)
    log_api_request(request, "/api/cve/refresh-data", user_ip, "Refreshing CVE data from trusted sources")
    
    try:
        cve_manager = await get_cve_manager()
        new_cves_count = await cve_manager.update_cve_data_from_sources()
        
        # Also fetch medical device specific CVEs
        medical_cves = await cve_manager.fetch_medical_device_cves()
        for cve in medical_cves:
            cve_manager.db.store_cve(cve)
        
        total_new_cves = new_cves_count + len(medical_cves)
        
        return APIResponse(
            success=True,
            message=f"Successfully refreshed CVE data. Added {total_new_cves} new/updated CVEs from trusted sources.",
            data={
                "new_cves_from_nvd": new_cves_count,
                "medical_device_cves": len(medical_cves),
                "total_new_cves": total_new_cves,
                "refresh_timestamp": datetime.now().isoformat(),
                "sources": ["NIST NVD", "Medical Device CVE Search"]
            }
        )
    except Exception as e:
        logger.error(f"Failed to refresh CVE data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to refresh CVE data: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )