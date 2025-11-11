#!/usr/bin/env python3
"""
AI Security Test Dashboard Server
Simple web server to serve the security testing dashboard
"""

import http.server
import socketserver
import webbrowser
import os
from pathlib import Path

class CORSHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP Request Handler with CORS support"""
    
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Forwarded-For, X-Real-IP, X-Originating-IP, User-Agent')
        super().end_headers()
    
    def do_OPTIONS(self):
        # Handle preflight requests
        self.send_response(200)
        self.end_headers()

def start_dashboard_server(port=8003):
    """Start the dashboard web server"""
    
    # Change to the directory containing the HTML file
    dashboard_dir = Path(__file__).parent
    os.chdir(dashboard_dir)
    
    print("🚀 Starting AI Security Test Dashboard Server...")
    print(f"📍 Server Directory: {dashboard_dir}")
    print(f"🌐 Server URL: http://localhost:{port}")
    print(f"📄 Dashboard: http://localhost:{port}/ai_security_test_dashboard.html")
    print("=" * 70)
    
    try:
        with socketserver.TCPServer(("", port), CORSHTTPRequestHandler) as httpd:
            print(f"✅ Dashboard server running on port {port}")
            print("🛡️ AI Security Testing Dashboard is ready!")
            print("\nFeatures available:")
            print("  • 🧪 Manual code testing with custom IP addresses")
            print("  • 📊 Real-time AI analysis results")
            print("  • 🎯 Preset malicious payloads for testing")
            print("  • 📈 Live statistics tracking")
            print("  • 🔍 Detailed risk scoring and reasoning")
            print("\nPress Ctrl+C to stop the server")
            print("=" * 70)
            
            # Try to open the dashboard in the browser
            try:
                dashboard_url = f"http://localhost:{port}/ai_security_test_dashboard.html"
                webbrowser.open(dashboard_url)
                print(f"🌐 Opening dashboard in your default browser...")
            except Exception as e:
                print(f"⚠️  Could not auto-open browser: {e}")
                print(f"🌐 Please manually open: http://localhost:{port}/ai_security_test_dashboard.html")
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Dashboard server stopped by user")
    except OSError as e:
        if e.errno == 10048:  # Port already in use
            print(f"❌ Port {port} is already in use!")
            print(f"💡 Try running with a different port:")
            print(f"   python dashboard_server.py --port 8004")
        else:
            print(f"❌ Server error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Security Test Dashboard Server")
    parser.add_argument("--port", type=int, default=8003, 
                       help="Port to run the dashboard server (default: 8003)")
    
    args = parser.parse_args()
    
    print("🛡️ AI Security Test Dashboard Server")
    print("🏥 Medical IoT Security Testing Interface")
    print("=" * 70)
    
    start_dashboard_server(args.port)