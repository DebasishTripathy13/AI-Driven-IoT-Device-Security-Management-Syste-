#!/usr/bin/env python3
"""
Simple startup script for the web server without reload complications
"""
import uvicorn
import sys
import os

def main():
    """Start the web server"""
    print("🚀 Starting Medical IoT Web Server...")
    print("📍 Web Interface: http://localhost:8000")
    print("🔗 API Server: http://localhost:8001")
    print("=" * 50)
    
    try:
        # Start the web server without reload to avoid conflicts
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,  # Use port 8000 
            reload=False,  # Disable reload to prevent conflicts
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n👋 Web server stopped by user")
    except Exception as e:
        print(f"❌ Error starting web server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()