#!/usr/bin/env python3
"""
AI Security Client - HTTP client for calling the AI Security Service
Used by the main API server to validate requests
"""

import json
import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AISecurityClient:
    def __init__(self, ai_service_url: str = "http://127.0.0.1:8002"):
        self.ai_service_url = ai_service_url
        self.timeout = 30.0  # 30 second timeout
        
    def analyze_request(self, method: str, path: str, headers: Dict[str, str], 
                            body: Optional[Dict[str, Any]], client_ip: str,
                            query_params: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Send request to AI security service for analysis
        
        Returns:
            Dict with keys: approved (bool), risk_score (int), reasons (list), etc.
        """
        try:
            logger.info(f"🤖 Sending request to AI security service: {method} {path}")
            
            # Prepare request data
            request_data = {
                "method": method,
                "path": path,
                "headers": headers or {},
                "body": body,
                "client_ip": client_ip,
                "query_params": query_params or {}
            }
            
            # Make HTTP request to AI service
            response = requests.post(
                f"{self.ai_service_url}/analyze",
                json=request_data,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"🛡️ AI Analysis: {'APPROVED' if result.get('approved') else 'BLOCKED'} - Risk: {result.get('risk_score', 0)}")
                return result
            else:
                logger.error(f"AI service error: {response.status_code} - {response.text}")
                # Default to block on service error for security
                return {
                    "approved": False,
                    "risk_score": 100,
                    "reasons": [f"AI service error: {response.status_code} - Request blocked for safety"],
                    "enhanced_payload": None,
                    "agent_recommendations": {"error": f"HTTP {response.status_code}"},
                    "processing_time_ms": 0
                }
                    
        except requests.exceptions.Timeout:
            logger.error("AI service timeout - blocking request for safety")
            return {
                "approved": False,
                "risk_score": 100,
                "reasons": ["AI service timeout - Request blocked for safety"],
                "enhanced_payload": None,
                "agent_recommendations": {"error": "timeout"},
                "processing_time_ms": 0
            }
            
        except Exception as e:
            logger.error(f"AI security client error: {e}")
            # Default to block on error for security
            return {
                "approved": False,
                "risk_score": 100,
                "reasons": [f"AI security error: {str(e)} - Request blocked for safety"],
                "enhanced_payload": None,
                "agent_recommendations": {"error": str(e)},
                "processing_time_ms": 0
            }
    
    def health_check(self) -> bool:
        """Check if AI security service is healthy"""
        try:
            response = requests.get(f"{self.ai_service_url}/health", timeout=5.0)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"AI service health check failed: {e}")
            return False
    
    def get_service_status(self) -> Optional[Dict[str, Any]]:
        """Get AI service status and configuration"""
        try:
            response = requests.get(f"{self.ai_service_url}/status", timeout=5.0)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Failed to get AI service status: {e}")
        return None

# Global AI security client instance
ai_security_client = AISecurityClient()