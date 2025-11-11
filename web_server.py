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
            <p><strong>Architecture:</strong></p>
            <ul>
                <li>Web Server (Port 8000): Serves static files and web interface</li>
                <li>API Server (Port 8001): Handles all device management and telemetry</li>
            </ul>
        </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Health check for web server"""
    return {"status": "healthy", "service": "web-server", "api_server": API_SERVER_URL}

# API Proxy Endpoints - Forward all API calls to the dedicated API server

@app.get("/api/devices")
async def get_devices(request: Request):
    """Get all registered devices - proxied to API server"""
    return await proxy_to_api_server(request, "/api/devices", "GET")

@app.get("/api/devices/{device_id}")
async def get_device(device_id: str, request: Request):
    """Get specific device - proxied to API server"""
    return await proxy_to_api_server(request, f"/api/devices/{device_id}", "GET")

@app.post("/api/devices/connect")
async def connect_devices(request: Request):
    """Connect devices - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, "/api/devices/connect", "POST", body)

@app.post("/api/devices/disconnect")
async def disconnect_devices(request: Request):
    """Disconnect devices - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, "/api/devices/disconnect", "POST", body)

@app.post("/api/telemetry/send")
async def send_telemetry(request: Request):
    """Send telemetry - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, "/api/telemetry/send", "POST", body)

@app.post("/api/telemetry/continuous")
async def start_continuous_telemetry(request: Request):
    """Start continuous telemetry - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, "/api/telemetry/continuous", "POST", body)

@app.get("/api/telemetry/sample/{device_type}")
async def get_sample_telemetry(device_type: str, request: Request):
    """Get sample telemetry - proxied to API server"""
    return await proxy_to_api_server(request, f"/api/telemetry/sample/{device_type}", "GET")

@app.post("/api/messages/send")
async def send_custom_message(request: Request):
    """Send custom message - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, "/api/messages/send", "POST", body)

@app.post("/api/devices/{device_id}/status")
async def check_device_status(device_id: str, request: Request):
    """Check device status - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, f"/api/devices/{device_id}/status", "POST", body)

@app.post("/api/devices/{device_id}/code")
async def execute_code_on_device(device_id: str, request: Request):
    """Execute code on device - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, f"/api/devices/{device_id}/code", "POST", body)

@app.patch("/api/devices/{device_id}")
async def update_device(device_id: str, request: Request):
    """Update device - proxied to API server"""
    body = await request.body()
    return await proxy_to_api_server(request, f"/api/devices/{device_id}", "PATCH", body)

@app.get("/api/status")
async def get_system_status(request: Request):
    """Get system status - proxied to API server"""
    return await proxy_to_api_server(request, "/api/status", "GET")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )