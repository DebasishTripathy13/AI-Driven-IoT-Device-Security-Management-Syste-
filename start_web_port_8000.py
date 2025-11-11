#!/usr/bin/env python3
"""
Start the main web server on port 8000 for IoT device management
"""
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    print("🌐 Starting IoT Device Manager Web Interface...")
    print("📍 Web Interface: http://localhost:8000")
    print("📍 Alternative: http://127.0.0.1:8000")
    
    try:
        uvicorn.run(
            "main:app",
            host="127.0.0.1",  # Use localhost specifically
            port=8000,  # Use port 8000 
            reload=False,  # Disable reload to avoid conflicts
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n👋 Shutting down web server...")
    except Exception as e:
        logger.error(f"Failed to start web server: {e}")