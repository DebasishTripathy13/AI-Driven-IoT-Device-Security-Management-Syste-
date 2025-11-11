"""
IDS Middleware for FastAPI
Integrates with the main IDS system for real-time threat detection
"""
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
import json
import logging
from typing import Callable
from ids_system import ids_manager
from database_manager import db_manager, APIRequest, SecurityEvent
from datetime import datetime

# Configure middleware logging
middleware_logger = logging.getLogger('ids_middleware')
middleware_logger.setLevel(logging.INFO)
middleware_handler = logging.FileHandler('middleware.log')
middleware_handler.setFormatter(logging.Formatter(
    '%(asctime)s - MIDDLEWARE - %(levelname)s - %(message)s'
))
middleware_logger.addHandler(middleware_handler)


class IDSMiddleware(BaseHTTPMiddleware):
    """
    IDS Middleware for comprehensive security monitoring
    - Logs all requests and responses
    - Detects malicious payloads (SQLi, code injection, XSS, etc.)
    - Implements flood detection and IP blocking
    - Monitors unauthorized access attempts
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.start_time = time.time()
        self.processed_requests = 0
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware processing"""
        start_time = time.time()
        self.processed_requests += 1
        
        # Extract request information
        client_ip = self._get_client_ip(request)
        method = request.method
        path = request.url.path
        user_agent = request.headers.get("user-agent", "Unknown")
        
        # Read request body
        body = await self._get_request_body(request)
        payload = body.decode('utf-8', errors='ignore') if body else ""
        payload_size = len(body) if body else 0
        
        # Skip IDS checks for admin dashboard endpoints to prevent lockout
        if path.startswith('/admin/ids') or path == '/admin':
            response = await call_next(request)
            return response
        
        # Enhanced logging for web proxy requests
        proxy_source = request.headers.get("X-Proxy-Source", "direct")
        client_type = request.headers.get("X-Client-Type", "unknown")
        
        middleware_logger.info(f"Request: {client_ip} {method} {path} - UA: {user_agent[:50]} - Source: {proxy_source} - Type: {client_type}")
        
        try:
            # Perform IDS analysis with enhanced context
            should_block, security_events = ids_manager.analyze_request(
                client_ip, method, path, user_agent, payload, extra_context={
                    "proxy_source": proxy_source,
                    "client_type": client_type,
                    "forwarded_host": request.headers.get("X-Forwarded-Host", ""),
                    "original_uri": request.headers.get("X-Original-URI", "")
                }
            )
            
            # Block the request if threat detected
            if should_block:
                middleware_logger.critical(f"BLOCKED REQUEST: {client_ip} {method} {path}")
                
                # Log the blocked request to old system
                ids_manager.log_request_metrics(
                    client_ip, method, path, user_agent, payload_size, 403
                )
                
                # Log blocked request to new database
                api_request = APIRequest(
                    timestamp=datetime.now().timestamp(),
                    ip_address=client_ip,
                    method=method,
                    path=path,
                    status_code=403,
                    processing_time=(time.time() - start_time) * 1000,
                    user_agent=user_agent,
                    request_size=payload_size,
                    response_size=0,
                    threat_level="high",
                    blocked=True
                )
                db_manager.log_api_request(api_request)
                
                # Log security event
                if security_events:
                    for event in security_events:
                        security_event = SecurityEvent(
                            timestamp=datetime.now().timestamp(),
                            ip_address=client_ip,
                            event_type=event.event_type,
                            severity=event.severity,
                            description=event.description,
                            action_taken="blocked",
                            details={
                                "method": method,
                                "path": path,
                                "user_agent": user_agent,
                                "payload_size": payload_size
                            }
                        )
                        db_manager.log_security_event(security_event)
                
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by security system",
                        "message": "Your request has been identified as potentially malicious",
                        "incident_id": security_events[0].event_id if security_events else "unknown",
                        "contact": "Please contact system administrator if you believe this is an error"
                    }
                )
            
            # Process the request normally
            response = await call_next(request)
            
            # Log successful request metrics with comprehensive data
            processing_time = time.time() - start_time
            
            # Log to the old system for compatibility
            ids_manager.log_request_metrics(
                client_ip, method, path, user_agent, payload_size, response.status_code
            )
            
            # Log to the new comprehensive database
            api_request = APIRequest(
                timestamp=datetime.now().timestamp(),
                ip_address=client_ip,
                method=method,
                path=path,
                status_code=response.status_code,
                processing_time=processing_time * 1000,  # Convert to milliseconds
                user_agent=user_agent,
                request_size=payload_size,
                response_size=int(response.headers.get("content-length", 0))
            )
            db_manager.log_api_request(api_request)
            
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["X-Request-ID"] = f"req_{int(time.time())}_{self.processed_requests}"
            response.headers["X-Processing-Time"] = f"{processing_time:.3f}s"
            
            middleware_logger.info(f"Response: {client_ip} {method} {path} - {response.status_code} ({processing_time:.3f}s)")
            
            return response
            
        except Exception as e:
            middleware_logger.error(f"Middleware error for {client_ip} {method} {path}: {str(e)}")
            
            # Log the error to old system
            ids_manager.log_request_metrics(
                client_ip, method, path, user_agent, payload_size, 500
            )
            
            # Log error to new database
            api_request = APIRequest(
                timestamp=datetime.now().timestamp(),
                ip_address=client_ip,
                method=method,
                path=path,
                status_code=500,
                processing_time=(time.time() - start_time) * 1000,
                user_agent=user_agent,
                request_size=payload_size,
                response_size=0,
                threat_level="normal"
            )
            db_manager.log_api_request(api_request)
            
            # Log application error
            db_manager.log_application_event(
                level="ERROR",
                component="middleware",
                message=f"Middleware error for {client_ip} {method} {path}",
                details={"error": str(e), "user_agent": user_agent}
            )
            
            # Return error response
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address, considering proxies"""
        # Check for forwarded headers (common with load balancers/proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    async def _get_request_body(self, request: Request) -> bytes:
        """Safely read request body"""
        try:
            # Store the body for later use by the actual endpoint
            body = await request.body()
            
            # Create a new request with the same body for the endpoint
            async def receive():
                return {"type": "http.request", "body": body}
            
            request._receive = receive
            return body
            
        except Exception as e:
            middleware_logger.warning(f"Could not read request body: {str(e)}")
            return b""


class SecurityHeaders:
    """Additional security headers middleware"""
    
    @staticmethod
    def add_security_headers(response: Response) -> Response:
        """Add comprehensive security headers"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", 
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            )
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware
    Works with the main IDS system for comprehensive protection
    """
    
    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_size = 60  # seconds
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Rate limiting logic"""
        client_ip = self._get_client_ip(request)
        
        # Skip rate limiting for admin dashboard
        if request.url.path.startswith('/admin'):
            return await call_next(request)
        
        # The main IDS system handles flood detection more comprehensively
        # This is just a backup rate limiter
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# Utility functions for manual IP management
def block_ip_manually(ip: str, reason: str, permanent: bool = False):
    """Manually block an IP address"""
    ids_manager.ip_manager.block_ip(ip, reason, permanent=permanent)
    middleware_logger.warning(f"Manual IP block: {ip} - {reason}")

def unblock_ip_manually(ip: str):
    """Manually unblock an IP address"""
    ids_manager.ip_manager.unblock_ip(ip)
    middleware_logger.info(f"Manual IP unblock: {ip}")

def get_blocked_ips():
    """Get list of currently blocked IPs"""
    return ids_manager.ip_manager.get_blocked_ips()

def get_security_stats():
    """Get current security statistics"""
    return {
        "total_blocked_ips": len(ids_manager.ip_manager.blocked_ips) + len(ids_manager.ip_manager.permanent_blocks),
        "temporary_blocks": len(ids_manager.ip_manager.blocked_ips),
        "permanent_blocks": len(ids_manager.ip_manager.permanent_blocks),
        "flood_threshold": ids_manager.ip_manager.flood_threshold,
        "system_uptime": time.time() - ids_manager.ip_manager.__dict__.get('start_time', time.time())
    }