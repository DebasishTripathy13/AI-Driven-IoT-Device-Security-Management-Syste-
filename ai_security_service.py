#!/usr/bin/env python3
"""
AI Security Service - Standalone service for AI-powered security analysis
Runs on port 8002 and provides security validation via HTTP API
"""

import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Import AI agents
try:
    from code_refactoring_agent import CodeRefactoringAgent
    from malicious_code_detection_agent import MaliciousCodeDetectionAgent
    from decision_making_agent import decision_agent, SecurityContext, RiskLevel, DecisionType
    from optimization_agent import OptimizationAgent
    from database_manager import DatabaseManager
    
    # Initialize AI agents
    refactoring_agent = CodeRefactoringAgent()
    optimization_agent = OptimizationAgent() 
    malware_agent = MaliciousCodeDetectionAgent()
    AI_AGENTS_AVAILABLE = True
    
except ImportError as e:
    print(f"Warning: AI agents not available - {e}")
    refactoring_agent = None
    optimization_agent = None
    malware_agent = None
    decision_agent = None
    AI_AGENTS_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Data models
class SecurityAnalysisRequest(BaseModel):
    method: str
    path: str
    headers: Dict[str, str] = {}
    body: Optional[Dict[str, Any]] = None
    client_ip: str = "unknown"
    query_params: Dict[str, str] = {}

class SecurityAnalysisResponse(BaseModel):
    approved: bool
    risk_score: int
    reasons: List[str]
    enhanced_payload: Optional[Dict[str, Any]] = None
    agent_recommendations: Dict[str, Any] = {}
    processing_time_ms: float

# FastAPI app
app = FastAPI(
    title="AI Security Service",
    description="Standalone AI-powered security analysis service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000", 
        "http://localhost:8001", 
        "http://localhost:8004",  # Dashboard server
        "http://127.0.0.1:8000", 
        "http://127.0.0.1:8001",
        "http://127.0.0.1:8004"   # Dashboard server
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AISecurityService:
    def __init__(self, risk_threshold: int = 50):
        self.risk_threshold = risk_threshold
        self.db = DatabaseManager()
        
        # Critical endpoints that require AI analysis
        self.critical_endpoints = [
            "/api/devices/{device_id}/code",
            "/api/devices/patch", 
            "/api/devices/update",
            "/api/messages/send"
        ]
        
        logger.info(f"AI Security Service initialized - AI Available: {AI_AGENTS_AVAILABLE}")

    async def analyze_request(self, request_data: SecurityAnalysisRequest) -> SecurityAnalysisResponse:
        """Perform comprehensive AI security analysis"""
        start_time = time.time()
        
        try:
            logger.info(f"🤖 Analyzing request: {request_data.method} {request_data.path} from {request_data.client_ip}")
            
            risk_score = 0
            reasons = []
            enhanced_payload = None
            agent_recommendations = {}
            
            # Phase 1: Malicious Code Detection
            if malware_agent and request_data.body:
                try:
                    payload_str = json.dumps(request_data.body)
                    
                    malware_result = malware_agent.scan_code_content(
                        payload_str,
                        "json", 
                        f"API request to {request_data.path}"
                    )
                    
                    risk_score += malware_result.get('risk_score', 0)
                    agent_recommendations['malware_scan'] = malware_result
                    
                    if malware_result.get('is_malicious', False):
                        reasons.append(f"Malicious code detected - Risk: {malware_result.get('risk_score', 0)}")
                        reasons.extend(malware_result.get('recommendations', [])[:2])
                        
                except Exception as e:
                    logger.error(f"Malware detection error: {e}")
                    risk_score += 10
                    reasons.append("Malware scan failed - proceeding with caution")
                    
            # Phase 2: Code Quality Analysis
            if refactoring_agent and self._is_code_related_request(request_data):
                try:
                    code_content = self._extract_code_from_request(request_data)
                    if code_content:
                        refactoring_result = refactoring_agent.analyze_code_quality(
                            code_content,
                            "python",
                            f"Code in API request to {request_data.path}"
                        )
                        
                        agent_recommendations['code_analysis'] = refactoring_result
                        
                        maintainability = refactoring_result.get('maintainability_score', 10)
                        if maintainability < 5:
                            risk_score += 20
                            reasons.append(f"Low code quality - Maintainability: {maintainability}/10")
                            
                except Exception as e:
                    logger.error(f"Code analysis error: {e}")
                    reasons.append("Code analysis failed - proceeding with caution")
            
            # Phase 3: Security Context Analysis
            if decision_agent and risk_score >= self.risk_threshold:
                try:
                    security_context = self._create_security_context(request_data)
                    
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
                        reasons.append("AI recommends human review - Request blocked")
                        risk_score += 30
                    elif decision_result.decision_type == DecisionType.POSTPONE:
                        reasons.append("AI recommends postponing request")
                        risk_score += 20
                        
                except Exception as e:
                    logger.error(f"AI decision error: {e}")
                    risk_score += 15
                    reasons.append("AI decision failed - using fallback rules")
            
            # Phase 4: Request Optimization
            if risk_score < self.risk_threshold and optimization_agent:
                try:
                    enhanced_payload = await self._optimize_request_payload(request_data)
                    if enhanced_payload:
                        reasons.append("Request optimized by AI")
                        agent_recommendations['optimization'] = {"enhanced": True}
                except Exception as e:
                    logger.error(f"Optimization error: {e}")
            
            # Final decision
            approved = risk_score < self.risk_threshold
            
            if not approved:
                reasons.insert(0, f"Request BLOCKED - Risk score {risk_score} exceeds threshold {self.risk_threshold}")
            else:
                reasons.insert(0, f"Request APPROVED - Risk score {risk_score} below threshold {self.risk_threshold}")
            
            # Store decision
            try:
                self._store_security_decision(request_data, risk_score, approved, reasons, agent_recommendations)
            except Exception as e:
                logger.error(f"Failed to store decision: {e}")
            
            processing_time = (time.time() - start_time) * 1000
            
            logger.info(f"🛡️ Analysis complete: {'APPROVED' if approved else 'BLOCKED'} - Risk: {risk_score} - Time: {processing_time:.1f}ms")
            
            return SecurityAnalysisResponse(
                approved=approved,
                risk_score=risk_score,
                reasons=reasons,
                enhanced_payload=enhanced_payload,
                agent_recommendations=agent_recommendations,
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            # Default to block if analysis fails for safety
            return SecurityAnalysisResponse(
                approved=False,
                risk_score=100,
                reasons=[f"Security analysis error: {str(e)} - Request blocked for safety"],
                agent_recommendations={"error": str(e)},
                processing_time_ms=(time.time() - start_time) * 1000
            )

    def _is_code_related_request(self, request_data: SecurityAnalysisRequest) -> bool:
        """Check if request contains code that needs analysis"""
        return "/code" in request_data.path or (
            request_data.body and "code" in str(request_data.body).lower()
        )

    def _extract_code_from_request(self, request_data: SecurityAnalysisRequest) -> Optional[str]:
        """Extract code content from request"""
        if not request_data.body:
            return None
            
        # Look for code in common fields
        for field in ['code', 'script', 'payload', 'content']:
            if field in request_data.body:
                return str(request_data.body[field])
        
        return None

    def _create_security_context(self, request_data: SecurityAnalysisRequest) -> SecurityContext:
        """Create security context for AI decision making"""
        return SecurityContext(
            device_id=request_data.body.get('deviceId', 'unknown') if request_data.body else 'unknown',
            device_type="medical_iot",
            device_criticality="high",
            current_threat_level=RiskLevel.MEDIUM,
            vulnerability_score=0.5,
            patch_urgency="normal",
            business_impact="moderate",
            historical_stability=0.95,
            network_exposure="limited",
            compliance_requirements=["HIPAA", "FDA"],
            operational_window={"start": "00:00", "end": "23:59"},
            recent_incidents=[]
        )

    async def _optimize_request_payload(self, request_data: SecurityAnalysisRequest) -> Optional[Dict[str, Any]]:
        """Optimize request payload if possible"""
        if not optimization_agent or not request_data.body:
            return None
            
        try:
            # Simple optimization - could be enhanced
            optimized = request_data.body.copy()
            
            # Add optimization metadata
            optimized['_ai_optimized'] = True
            optimized['_optimization_timestamp'] = datetime.now().isoformat()
            
            return optimized
        except Exception as e:
            logger.error(f"Payload optimization failed: {e}")
            return None

    def _store_security_decision(self, request_data: SecurityAnalysisRequest, risk_score: int, 
                               approved: bool, reasons: List[str], recommendations: Dict[str, Any]):
        """Store security decision in database"""
        try:
            event_data = {
                "event_type": "ai_security_decision",
                "method": request_data.method,
                "path": request_data.path,
                "client_ip": request_data.client_ip,
                "risk_score": risk_score,
                "approved": approved,
                "reasons": json.dumps(reasons),
                "agent_recommendations": json.dumps(recommendations),
                "timestamp": datetime.now().isoformat()
            }
            
            self.db.log_security_event(
                event_type="ai_security_decision",
                severity="high" if not approved else "info",
                description=f"AI Security Analysis: {'BLOCKED' if not approved else 'APPROVED'}",
                device_id=request_data.body.get('deviceId', 'unknown') if request_data.body else 'unknown',
                source_ip=request_data.client_ip,
                endpoint=request_data.path,
                details={"risk_score": total_risk, "reasons": reasons, "recommendations": recommendations}
            )
            
        except Exception as e:
            logger.error(f"Failed to store security decision: {e}")

# Global service instance
security_service = AISecurityService()

# API endpoints
@app.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_request(request: SecurityAnalysisRequest):
    """Analyze a request for security threats"""
    return await security_service.analyze_request(request)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "ai_agents_available": AI_AGENTS_AVAILABLE,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status")
async def get_status():
    """Get service status and configuration"""
    return {
        "service": "AI Security Service",
        "version": "1.0.0",
        "ai_agents_available": AI_AGENTS_AVAILABLE,
        "risk_threshold": security_service.risk_threshold,
        "critical_endpoints": security_service.critical_endpoints,
        "agents": {
            "malware_detection": malware_agent is not None,
            "code_refactoring": refactoring_agent is not None,
            "decision_making": decision_agent is not None,
            "optimization": optimization_agent is not None
        }
    }

if __name__ == "__main__":
    print("🚀 Starting AI Security Service on port 8002...")
    print("🤖 AI Agents Available:", AI_AGENTS_AVAILABLE)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8002,
        log_level="info",
        access_log=True
    )