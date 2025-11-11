"""
AI Security Middleware for Medical IoT Device Manager
Integrates AI agents directly into the API request flow for real-time security validation
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Import AI agents
try:
    from code_refactoring_agent import CodeRefactoringAgent
    from optimization_agent import OptimizationAgent
    from malicious_code_detection_agent import MaliciousCodeDetectionAgent
    from decision_making_agent import decision_agent, SecurityContext, RiskLevel, DecisionType
    AI_AGENTS_AVAILABLE = True
    
    # Initialize agents
    refactoring_agent = CodeRefactoringAgent()
    optimization_agent = OptimizationAgent()
    malware_agent = MaliciousCodeDetectionAgent()
    
except ImportError as e:
    logging.warning(f"AI agents not available: {e}")
    AI_AGENTS_AVAILABLE = False
    refactoring_agent = None
    optimization_agent = None
    malware_agent = None

from database_manager import db_manager

# Configure logging
logger = logging.getLogger(__name__)

class AISecurityDecision:
    """Represents a security decision made by AI agents"""
    def __init__(self, approved: bool, risk_score: int, reasons: list, 
                 enhanced_payload: Optional[Dict] = None, agent_recommendations: Optional[Dict] = None):
        self.approved = approved
        self.risk_score = risk_score
        self.reasons = reasons
        self.enhanced_payload = enhanced_payload
        self.agent_recommendations = agent_recommendations or {}
        self.timestamp = datetime.now().isoformat()
        self.decision_id = f"decision-{int(time.time())}"

class AISecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware that integrates AI agents into the API request flow
    All API requests pass through AI security validation before processing
    """
    
    def __init__(self, app, enable_ai_filtering: bool = True, 
                 risk_threshold: int = 70, optimization_enabled: bool = True):
        super().__init__(app)
        self.enable_ai_filtering = enable_ai_filtering and AI_AGENTS_AVAILABLE
        self.risk_threshold = risk_threshold
        self.optimization_enabled = optimization_enabled
        
        # Trusted IPs that bypass AI filtering (authentic local requests)
        self.trusted_ips = [
            "127.0.0.1",
            "::1",  # IPv6 localhost
            "localhost"
        ]
        
        # Track protected endpoints that require AI validation
        self.protected_endpoints = [
            "/api/telemetry/send",
            "/api/devices/patch",
            "/api/devices/message", 
            "/api/devices/update",
            "/api/devices/configure",
            "/api/devices/",  # Covers /api/devices/{device_id}
            "/api/messages/send",
            "/api/devices/{device_id}/code",
            "/api/devices/{device_id}/status"
        ]
        
        # Endpoints to exclude from AI filtering (admin, health checks, etc.)
        self.excluded_endpoints = [
            "/admin",
            "/health",
            "/api/ai",
            "/docs",
            "/openapi.json",
            "/favicon.ico"
        ]
        
        logger.info(f"AI Security Middleware initialized - AI Filtering: {self.enable_ai_filtering}")
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        
        # Skip AI filtering for excluded endpoints
        if self._should_skip_ai_filtering(request.url.path):
            return await call_next(request)
        
        # Record request start time
        start_time = time.time()
        
        try:
            # Get request details
            request_data = await self._extract_request_data(request)
            
            # Check if request is from trusted IP
            client_ip = request_data.get('client_ip', 'unknown')
            is_trusted_ip = self._is_trusted_ip(client_ip)
            
            # Check for test mode header to force AI analysis even for trusted IPs
            force_ai_analysis = request.headers.get('X-Force-AI-Analysis', '').lower() == 'true'
            
            # Define critical endpoints that ALWAYS require AI analysis (even from trusted IPs)
            critical_endpoints = [
                "/api/devices/{device_id}/code",     # Code execution - ALWAYS analyze
                "/api/devices/patch",                # Patching devices - ALWAYS analyze  
                "/api/devices/update",               # Device updates - ALWAYS analyze
                "/api/messages/send"                 # Custom messages - ALWAYS analyze
            ]
            
            is_critical_endpoint = any(endpoint in request.url.path for endpoint in critical_endpoints)
            
            # Skip AI analysis only for trusted IPs on non-critical endpoints
            if (is_trusted_ip and not force_ai_analysis and not is_critical_endpoint and 
                not any(endpoint in request.url.path for endpoint in self.protected_endpoints)):
                logger.info(f"Trusted IP {client_ip} - bypassing AI security filtering for non-critical endpoint")
                self._log_trusted_request(request, request_data)
                response = await call_next(request)
                processing_time = time.time() - start_time
                self._log_response_metrics(request, response, processing_time)
                return response
            elif is_critical_endpoint:
                logger.info(f"CRITICAL ENDPOINT: {client_ip} - AI analysis REQUIRED regardless of trust level")
            elif force_ai_analysis:
                logger.info(f"FORCED AI ANALYSIS: {client_ip} (test mode enabled)")
            
            # Log all API requests
            self._log_api_request(request, request_data)
            
            # Run AI security analysis if enabled and endpoint is protected
            if (self.enable_ai_filtering and 
                any(endpoint in request.url.path for endpoint in self.protected_endpoints)):
                
                logger.info(f"🤖 AI SECURITY ANALYSIS TRIGGERED for {request.method} {request.url.path} from {client_ip}")
                
                # Perform AI security validation
                security_decision = await self._ai_security_validation(request, request_data)
                
                logger.info(f"🛡️ AI DECISION: {'APPROVED' if security_decision.approved else 'BLOCKED'} - Risk Score: {security_decision.risk_score}")
                
                # Block request if AI determines it's malicious
                if not security_decision.approved:
                    logger.warning(f"🚫 BLOCKING MALICIOUS REQUEST: {security_decision.reasons}")
                    return self._create_blocked_response(security_decision)
                
                # Enhance request if AI suggests improvements
                if security_decision.enhanced_payload:
                    logger.info(f"✨ AI ENHANCED REQUEST with optimizations")
                    request = await self._enhance_request(request, security_decision.enhanced_payload)
            
            # Process the request
            response = await call_next(request)
            
            # Log response and performance metrics
            processing_time = time.time() - start_time
            self._log_response_metrics(request, response, processing_time)
            
            return response
            
        except Exception as e:
            logger.error(f"AI Security Middleware error: {e}")
            # Continue with original request if AI processing fails
            return await call_next(request)
    
    def _is_trusted_ip(self, client_ip: str) -> bool:
        """Check if client IP is in trusted list (authentic local requests)"""
        if not client_ip or client_ip == "unknown":
            return False
        
        # Check exact match
        if client_ip in self.trusted_ips:
            return True
        
        # Check for localhost variations
        if client_ip.startswith("127.") or client_ip == "::1":
            return True
            
        return False
    
    def _log_trusted_request(self, request: Request, request_data: Dict[str, Any]):
        """Log trusted IP request"""
        try:
            logger.info(f"TRUSTED REQUEST - IP: {request_data['client_ip']} | "
                       f"Method: {request_data['method']} | Path: {request_data['path']}")
            
            # Store in database as trusted request
            db_manager.log_security_event(
                event_type="trusted_request",
                severity="info",
                description=f"Request from trusted IP bypassed AI filtering",
                source_ip=request_data['client_ip'],
                additional_data={
                    "method": request_data['method'],
                    "path": request_data['path'],
                    "ai_filtering_bypassed": True,
                    "reason": "trusted_ip"
                }
            )
        except Exception as e:
            logger.warning(f"Failed to log trusted request: {e}")
    
    def _should_skip_ai_filtering(self, path: str) -> bool:
        """Determine if a request should skip AI filtering"""
        return any(excluded in path for excluded in self.excluded_endpoints)
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract request data for AI analysis"""
        try:
            # Get request body if it exists
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                if body:
                    try:
                        body = json.loads(body.decode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        body = body.decode('utf-8', errors='ignore')
            
            return {
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": dict(request.headers),
                "body": body,
                "client_ip": request.client.host if request.client else "unknown"
            }
            
        except Exception as e:
            logger.warning(f"Failed to extract request data: {e}")
            return {
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else "unknown",
                "extraction_error": str(e)
            }
    
    async def _ai_security_validation(self, request: Request, request_data: Dict[str, Any]) -> AISecurityDecision:
        """
        Run comprehensive AI security validation on the request
        """
        try:
            logger.info(f"Running AI security validation for {request_data['method']} {request_data['path']}")
            
            risk_score = 0
            reasons = []
            enhanced_payload = None
            agent_recommendations = {}
            
            # Phase 1: Malicious Code Detection
            if malware_agent and request_data.get('body') and isinstance(request_data['body'], (str, dict)):
                try:
                    payload_str = json.dumps(request_data['body']) if isinstance(request_data['body'], dict) else str(request_data['body'])
                    
                    # Scan for malicious patterns
                    malware_result = malware_agent.scan_code_content(
                        payload_str, 
                        "json", 
                        f"API request to {request_data['path']}"
                    )
                    
                    risk_score += malware_result.get('risk_score', 0)
                    agent_recommendations['malware_scan'] = malware_result
                    
                    if malware_result.get('is_malicious', False):
                        reasons.append(f"Malicious code detected - Risk: {malware_result.get('risk_score', 0)}")
                        reasons.extend(malware_result.get('recommendations', [])[:2])
                        
                except Exception as e:
                    logger.error(f"Malware detection failed: {e}")
                    risk_score += 10  # Add some risk if scanning fails
                    reasons.append(f"Malware scan error - proceeding with caution: {str(e)[:50]}")
                    
            elif not malware_agent and request_data.get('body'):
                logger.warning("Malware agent not available - skipping malicious code detection")
                reasons.append("Malware detection unavailable - proceeding with caution")
            
            # Phase 2: Code Quality Analysis (for code-related requests)
            if refactoring_agent and self._is_code_related_request(request_data):
                try:
                    code_content = self._extract_code_from_request(request_data)
                    if code_content:
                        refactoring_result = refactoring_agent.analyze_code_quality(
                            code_content,
                            "python",  # Assume Python for IoT devices
                            f"Code in API request to {request_data['path']}"
                        )
                        
                        agent_recommendations['code_analysis'] = refactoring_result
                        
                        # Penalize low-quality code
                        maintainability = refactoring_result.get('maintainability_score', 10)
                        if maintainability < 5:
                            risk_score += 20
                            reasons.append(f"Low code quality detected - Maintainability: {maintainability}/10")
                except Exception as e:
                    logger.error(f"Code analysis failed: {e}")
                    reasons.append(f"Code analysis error - proceeding with caution: {str(e)[:50]}")
                    
            elif not refactoring_agent and self._is_code_related_request(request_data):
                logger.warning("Code refactoring agent not available - skipping code quality analysis")
            
            # Phase 3: System Context Analysis
            security_context = self._create_security_context(request_data)
            
            # Make AI security decision
            if decision_agent and risk_score >= self.risk_threshold:
                try:
                    decision_result = await decision_agent.make_security_decision(
                        security_context=security_context,
                        patch_info={
                            "severity": "HIGH" if risk_score >= 80 else "MEDIUM",
                            "description": f"API request validation - Risk score: {risk_score}"
                        }
                    )
                    
                    agent_recommendations['ai_decision'] = {
                        "decision_type": decision_result.decision_type.value,
                        "confidence": decision_result.confidence_level.value,
                        "reasoning": decision_result.reasoning
                    }
                    
                    if decision_result.decision_type == DecisionType.ESCALATE_HUMAN:
                        reasons.append("AI recommends human review - Request blocked for safety")
                        risk_score += 30
                    elif decision_result.decision_type == DecisionType.POSTPONE:
                        reasons.append("AI recommends postponing request")
                        risk_score += 20
                except Exception as e:
                    logger.error(f"AI decision making failed: {e}")
                    reasons.append(f"AI decision error - using fallback security rules: {str(e)[:50]}")
                    risk_score += 15  # Add some penalty for failed AI analysis
                    
            elif not decision_agent and risk_score >= self.risk_threshold:
                logger.warning("Decision agent not available - using basic risk threshold logic")
                reasons.append("AI decision agent unavailable - using basic security rules")
            
            # Phase 4: Request Optimization (if approved and enabled)
            if risk_score < self.risk_threshold and self.optimization_enabled:
                enhanced_payload = await self._optimize_request_payload(request_data)
                if enhanced_payload:
                    reasons.append("Request optimized by AI for better performance")
                    agent_recommendations['optimization'] = {"enhanced": True}
            
            # Final decision
            approved = risk_score < self.risk_threshold
            
            if not approved:
                reasons.insert(0, f"Request blocked - Risk score {risk_score} exceeds threshold {self.risk_threshold}")
            
            # Store decision in database
            try:
                self._store_security_decision(request_data, risk_score, approved, reasons, agent_recommendations)
            except Exception as e:
                logger.error(f"Failed to store security decision: {e}")
                # Don't fail the request if database storage fails
            
            return AISecurityDecision(
                approved=approved,
                risk_score=risk_score,
                reasons=reasons,
                enhanced_payload=enhanced_payload,
                agent_recommendations=agent_recommendations
            )
            
        except Exception as e:
            logger.error(f"AI security validation error: {e}")
            # Default to allowing request if AI analysis fails
            return AISecurityDecision(
                approved=True,
                risk_score=0,
                reasons=[f"AI validation error: {str(e)} - Request allowed by default"],
                agent_recommendations={"error": str(e)}
            )
    
    def _is_code_related_request(self, request_data: Dict[str, Any]) -> bool:
        """Check if request contains code that should be analyzed"""
        code_indicators = ["patch", "update", "configure", "script", "firmware"]
        path = request_data.get('path', '').lower()
        return any(indicator in path for indicator in code_indicators)
    
    def _extract_code_from_request(self, request_data: Dict[str, Any]) -> Optional[str]:
        """Extract potential code content from request for analysis"""
        body = request_data.get('body')
        if not body:
            return None
        
        if isinstance(body, dict):
            # Look for common code fields
            code_fields = ['code', 'script', 'firmware', 'patch_data', 'configuration', 'payload']
            for field in code_fields:
                if field in body:
                    return str(body[field])
            
            # Return entire body as JSON string for analysis
            return json.dumps(body, indent=2)
        
        return str(body)
    
    def _create_security_context(self, request_data: Dict[str, Any]) -> SecurityContext:
        """Create security context for AI decision making"""
        # Determine device criticality based on request path
        path = request_data.get('path', '')
        device_criticality = "high" if any(critical in path for critical in ['medical', 'critical', 'emergency']) else "standard"
        
        # Determine threat level based on request characteristics
        threat_level = RiskLevel.HIGH if request_data.get('method') in ['POST', 'PUT', 'DELETE'] else RiskLevel.MEDIUM
        
        return SecurityContext(
            device_id=request_data.get('body', {}).get('deviceId', 'api-request') if isinstance(request_data.get('body'), dict) else 'api-request',
            device_type="API Endpoint",
            device_criticality=device_criticality,
            current_threat_level=threat_level,
            vulnerability_score=5.0,  # Default score
            patch_urgency="medium",
            business_impact="medium",
            historical_stability=0.85,
            network_exposure="internal",
            compliance_requirements=["ISO27001", "HIPAA"],
            operational_window={"maintenance_hours": "02:00-04:00"},
            recent_incidents=[]
        )
    
    async def _optimize_request_payload(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use optimization agent to enhance request payload"""
        try:
            if not request_data.get('body') or not isinstance(request_data['body'], dict):
                return None
            
            # Run system optimization analysis
            optimization_report = optimization_agent.run_comprehensive_analysis()
            
            # Create enhanced payload based on optimization recommendations
            enhanced = request_data['body'].copy()
            
            # Add optimization metadata
            enhanced['_ai_optimization'] = {
                "timestamp": datetime.now().isoformat(),
                "health_score": optimization_report.get('overall_health_score', 0),
                "optimizations_applied": [],
                "recommendations": optimization_report.get('recommendations', {}).get('immediate_actions', [])[:3]
            }
            
            # Apply basic optimizations
            if 'timeout' not in enhanced and request_data['path'] in ['/api/telemetry/send', '/api/devices/message']:
                enhanced['timeout'] = 30000  # Add reasonable timeout
                enhanced['_ai_optimization']['optimizations_applied'].append("Added timeout parameter")
            
            if 'retry_count' not in enhanced:
                enhanced['retry_count'] = 3  # Add retry logic
                enhanced['_ai_optimization']['optimizations_applied'].append("Added retry logic")
            
            return enhanced if enhanced['_ai_optimization']['optimizations_applied'] else None
            
        except Exception as e:
            logger.warning(f"Request optimization failed: {e}")
            return None
    
    async def _enhance_request(self, request: Request, enhanced_payload: Dict[str, Any]) -> Request:
        """Replace request body with AI-enhanced version"""
        try:
            # Create new request with enhanced payload
            enhanced_body = json.dumps(enhanced_payload).encode('utf-8')
            
            # Note: In practice, you might need to create a new Request object
            # This is a simplified approach - in production, consider using request modification techniques
            request._body = enhanced_body
            
            return request
            
        except Exception as e:
            logger.warning(f"Request enhancement failed: {e}")
            return request
    
    def _create_blocked_response(self, security_decision: AISecurityDecision) -> JSONResponse:
        """Create response for blocked requests"""
        
        # Log blocked request
        logger.warning(f"Request blocked by AI security - Risk: {security_decision.risk_score}")
        
        response_data = {
            "error": "Request blocked by AI security system",
            "decision_id": security_decision.decision_id,
            "risk_score": security_decision.risk_score,
            "reasons": security_decision.reasons,
            "timestamp": security_decision.timestamp,
            "contact_admin": "Contact system administrator if you believe this is an error"
        }
        
        return JSONResponse(
            status_code=403,
            content=response_data,
            headers={"X-AI-Security-Decision": security_decision.decision_id}
        )
    
    def _log_api_request(self, request: Request, request_data: Dict[str, Any]):
        """Log API request for monitoring"""
        try:
            db_manager.log_api_request(
                timestamp=datetime.now().isoformat(),
                method=request_data['method'],
                endpoint=request_data['path'],
                status_code=0,  # Will be updated in response logging
                ip_address=request_data['client_ip'],
                user_agent=request_data.get('headers', {}).get('user-agent', 'Unknown'),
                request_size=len(str(request_data.get('body', ''))),
                geographic_info={"country": "Unknown", "city": "Unknown"}  # Would be enhanced with actual geo lookup
            )
        except Exception as e:
            logger.warning(f"Failed to log API request: {e}")
    
    def _log_response_metrics(self, request: Request, response: Response, processing_time: float):
        """Log response metrics"""
        try:
            # Log performance metrics for optimization agent
            logger.info(f"Request processed: {request.method} {request.url.path} - "
                       f"Status: {response.status_code} - Time: {processing_time:.3f}s")
        except Exception as e:
            logger.warning(f"Failed to log response metrics: {e}")
    
    def _store_security_decision(self, request_data: Dict[str, Any], risk_score: int, 
                               approved: bool, reasons: list, agent_recommendations: Dict[str, Any]):
        """Store AI security decision in database"""
        try:
            db_manager.log_security_event(
                event_type="ai_security_decision",
                severity="high" if not approved else "info",
                description=f"AI security decision for {request_data['method']} {request_data['path']}",
                source_ip=request_data['client_ip'],
                additional_data={
                    "risk_score": risk_score,
                    "approved": approved,
                    "reasons": reasons,
                    "agent_recommendations": agent_recommendations,
                    "request_method": request_data['method'],
                    "request_path": request_data['path']
                }
            )
        except Exception as e:
            logger.warning(f"Failed to store security decision: {e}")

# Create middleware instance
ai_security_middleware = AISecurityMiddleware