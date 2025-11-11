"""
AI Agent Integration API Endpoints
Integrates the AI security agents with the main API server
Provides endpoints to trigger AI security assessments and get results
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List, Any
import logging
import asyncio
from datetime import datetime

# Import AI agents
try:
    from ai_agent_coordinator import coordinator
    from proactive_monitoring_agent import monitoring_agent
    from decision_making_agent import decision_agent, SecurityContext, RiskLevel
    AI_AGENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"AI agents not available: {e}")
    AI_AGENTS_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Create router for AI agent endpoints
ai_router = APIRouter(prefix="/ai", tags=["AI Security Agents"])

@ai_router.get("/status")
async def get_ai_system_status():
    """Get AI security system status"""
    if not AI_AGENTS_AVAILABLE:
        return {"status": "unavailable", "message": "AI agents not installed"}
    
    try:
        status = await coordinator.get_system_status()
        return {
            "status": "active",
            "system_health": status.system_health,
            "agents_active": status.agents_active,
            "total_devices_monitored": status.total_devices_monitored,
            "active_vulnerabilities": status.active_vulnerabilities,
            "pending_patches": status.pending_patches,
            "recent_decisions": status.recent_decisions,
            "timestamp": status.timestamp
        }
    except Exception as e:
        logger.error(f"Failed to get AI system status: {e}")
        raise HTTPException(status_code=500, detail=f"AI system error: {str(e)}")

@ai_router.post("/security-assessment")
async def run_security_assessment(background_tasks: BackgroundTasks):
    """Trigger comprehensive AI security assessment"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        # Get current devices (you'll need to import your device list)
        devices = [
            {
                "deviceId": "med-ecg-001",
                "deviceType": "Medical ECG Monitor",
                "manufacturer": "Philips",
                "firmwareVersion": "2.1.3",
                "softwareVersion": "Linux 4.14.0",
                "osName": "Embedded Linux"
            },
            {
                "deviceId": "hvac-controller-002", 
                "deviceType": "HVAC Controller",
                "manufacturer": "Honeywell",
                "firmwareVersion": "3.2.1",
                "softwareVersion": "FreeRTOS 10.4",
                "osName": "FreeRTOS"
            },
            {
                "deviceId": "security-camera-003",
                "deviceType": "IP Security Camera", 
                "manufacturer": "Hikvision",
                "firmwareVersion": "5.7.1",
                "softwareVersion": "Linux 3.18",
                "osName": "Embedded Linux"
            }
        ]
        
        # Run assessment in background
        assessment_id = f"assessment-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Schedule background task
        background_tasks.add_task(run_full_assessment, assessment_id, devices)
        
        return {
            "assessment_id": assessment_id,
            "status": "started",
            "message": "AI security assessment initiated",
            "devices_count": len(devices),
            "estimated_duration": "2-5 minutes"
        }
        
    except Exception as e:
        logger.error(f"Failed to start security assessment: {e}")
        raise HTTPException(status_code=500, detail=f"Assessment error: {str(e)}")

async def run_full_assessment(assessment_id: str, devices: List[Dict[str, Any]]):
    """Background task to run full AI security assessment"""
    try:
        logger.info(f"Starting AI security assessment {assessment_id}")
        
        # Run the full security cycle
        results = await coordinator.run_full_security_cycle(devices)
        
        # Store results (in production, you'd save to database)
        logger.info(f"AI assessment {assessment_id} completed: {results}")
        
    except Exception as e:
        logger.error(f"AI assessment {assessment_id} failed: {e}")

@ai_router.get("/vulnerabilities")
async def get_vulnerability_assessment():
    """Get latest vulnerability assessment results"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        # Get sample devices for assessment
        devices = [
            {
                "deviceId": "med-ecg-001",
                "deviceType": "Medical ECG Monitor",
                "manufacturer": "Philips", 
                "firmwareVersion": "2.1.3",
                "osName": "Embedded Linux"
            }
        ]
        
        # Run vulnerability assessment
        assessments = await monitoring_agent.assess_device_vulnerabilities(devices)
        
        vulnerability_data = []
        for assessment in assessments:
            vulnerability_data.append({
                "device_id": assessment.device_id,
                "device_type": assessment.device_type,
                "firmware_version": assessment.firmware_version,
                "risk_score": assessment.risk_score,
                "cve_count": len(assessment.cve_matches),
                "recommendations": assessment.recommendations[:3],  # Top 3
                "last_assessed": assessment.last_assessed
            })
        
        return {
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities_found": len(vulnerability_data),
            "devices_assessed": len(devices),
            "vulnerability_data": vulnerability_data
        }
        
    except Exception as e:
        logger.error(f"Failed to get vulnerability assessment: {e}")
        raise HTTPException(status_code=500, detail=f"Vulnerability assessment error: {str(e)}")

@ai_router.post("/ai-decision")
async def make_ai_security_decision(request_data: Dict[str, Any]):
    """Make AI-powered security decision"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        # Create security context from request
        security_context = SecurityContext(
            device_id=request_data.get('device_id', 'unknown'),
            device_type=request_data.get('device_type', 'IoT Device'),
            device_criticality=request_data.get('device_criticality', 'standard'),
            current_threat_level=RiskLevel(request_data.get('threat_level', 'MEDIUM')),
            vulnerability_score=float(request_data.get('vulnerability_score', 5.0)),
            patch_urgency=request_data.get('patch_urgency', 'medium'),
            business_impact=request_data.get('business_impact', 'medium'),
            historical_stability=float(request_data.get('stability', 0.85)),
            network_exposure=request_data.get('network_exposure', 'internal'),
            compliance_requirements=request_data.get('compliance', []),
            operational_window=request_data.get('operational_window', {}),
            recent_incidents=request_data.get('recent_incidents', [])
        )
        
        # Make AI decision
        decision = await decision_agent.make_security_decision(
            security_context=security_context,
            patch_info=request_data.get('patch_info', {})
        )
        
        return {
            "decision_id": decision.decision_id,
            "timestamp": decision.timestamp,
            "decision_type": decision.decision_type.value,
            "confidence_level": decision.confidence_level.value,
            "risk_assessment": decision.risk_assessment.value,
            "reasoning": decision.reasoning,
            "supporting_evidence": decision.supporting_evidence,
            "recommended_timeline": decision.recommended_timeline,
            "success_probability": decision.success_probability,
            "potential_risks": decision.potential_risks,
            "monitoring_requirements": decision.monitoring_requirements
        }
        
    except Exception as e:
        logger.error(f"Failed to make AI decision: {e}")
        raise HTTPException(status_code=500, detail=f"AI decision error: {str(e)}")

@ai_router.get("/cve-updates")
async def get_latest_cve_updates():
    """Get latest CVE updates from monitoring agent"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        # Fetch recent CVEs
        cves = await monitoring_agent.fetch_cve_data(days_back=1)
        
        cve_summary = []
        for cve in cves[:10]:  # Top 10 most recent
            cve_summary.append({
                "cve_id": cve.cve_id,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "severity": cve.severity.value,
                "score": cve.score,
                "published_date": cve.published_date,
                "affected_software": cve.affected_software[:3],  # First 3
                "exploit_available": cve.exploit_available
            })
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_cves_fetched": len(cves),
            "recent_cves": cve_summary,
            "high_severity_count": len([c for c in cves if c.severity.value in ['HIGH', 'CRITICAL']]),
            "exploitable_count": len([c for c in cves if c.exploit_available])
        }
        
    except Exception as e:
        logger.error(f"Failed to get CVE updates: {e}")
        raise HTTPException(status_code=500, detail=f"CVE update error: {str(e)}")

@ai_router.post("/code-analysis")
async def run_code_analysis(request_data: Dict[str, Any]):
    """Run code refactoring analysis using AI"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        code_content = request_data.get('code_content', '')
        file_type = request_data.get('file_type', 'python')
        context = request_data.get('context', '')
        
        if not code_content:
            raise HTTPException(status_code=400, detail="Code content is required")
        
        # Run code refactoring analysis
        refactoring_agent = coordinator.agents["code_refactoring"]
        analysis = refactoring_agent.analyze_code_quality(code_content, file_type, context)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_id": f"analysis-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "maintainability_score": analysis.get("maintainability_score", 0),
            "issues_found": len(analysis.get("issues", [])),
            "suggestions_count": len(analysis.get("suggestions", [])),
            "issues": analysis.get("issues", [])[:5],  # Top 5 issues
            "suggestions": analysis.get("suggestions", [])[:5],  # Top 5 suggestions
            "overall_assessment": analysis.get("overall_assessment", ""),
            "file_type": file_type
        }
        
    except Exception as e:
        logger.error(f"Failed to run code analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Code analysis error: {str(e)}")

@ai_router.post("/malware-scan")
async def run_malware_scan(request_data: Dict[str, Any]):
    """Run malicious code detection scan"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        code_content = request_data.get('code_content', '')
        file_type = request_data.get('file_type', 'python')
        context = request_data.get('context', '')
        
        if not code_content:
            raise HTTPException(status_code=400, detail="Code content is required")
        
        # Run malware detection
        malware_agent = coordinator.agents["malicious_code_detection"]
        scan_result = malware_agent.scan_code_content(code_content, file_type, context)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "scan_id": f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "risk_score": scan_result.get("risk_score", 0),
            "is_malicious": scan_result.get("is_malicious", False),
            "severity": scan_result.get("severity", "clean"),
            "pattern_matches": len(scan_result.get("pattern_matches", [])),
            "ai_threat_level": scan_result.get("ai_analysis", {}).get("threat_level", "none"),
            "malicious_probability": scan_result.get("ai_analysis", {}).get("malicious_probability", 0),
            "suspicious_behaviors": scan_result.get("ai_analysis", {}).get("suspicious_behaviors", [])[:3],
            "recommendations": scan_result.get("recommendations", [])[:5],
            "file_type": file_type
        }
        
    except Exception as e:
        logger.error(f"Failed to run malware scan: {e}")
        raise HTTPException(status_code=500, detail=f"Malware scan error: {str(e)}")

@ai_router.get("/system-optimization")
async def get_system_optimization():
    """Get system optimization analysis and recommendations"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        # Run comprehensive optimization analysis
        optimization_agent = coordinator.agents["optimization"]
        optimization_report = optimization_agent.run_comprehensive_analysis()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "overall_health_score": optimization_report.get("overall_health_score", 0),
            "system_metrics": {
                "cpu_usage": optimization_report.get("system_metrics", {}).get("cpu", {}).get("usage_percent", 0),
                "memory_usage": optimization_report.get("system_metrics", {}).get("memory", {}).get("percent", 0),
                "disk_usage": optimization_report.get("system_metrics", {}).get("disk", {}).get("percent", 0)
            },
            "performance_trends": {
                "bottlenecks_count": len(optimization_report.get("performance_trends", {}).get("bottlenecks", [])),
                "cpu_trend": optimization_report.get("performance_trends", {}).get("cpu_analysis", {}).get("trend", "stable"),
                "memory_trend": optimization_report.get("performance_trends", {}).get("memory_analysis", {}).get("trend", "stable")
            },
            "api_performance": {
                "avg_response_time": optimization_report.get("api_analysis", {}).get("metrics", {}).get("avg_response_time_ms", 0),
                "error_rate": optimization_report.get("api_analysis", {}).get("metrics", {}).get("error_rate_percent", 0),
                "throughput": optimization_report.get("api_analysis", {}).get("metrics", {}).get("throughput_rpm", 0)
            },
            "recommendations": {
                "immediate_actions": optimization_report.get("recommendations", {}).get("immediate_actions", [])[:5],
                "priority_score": optimization_report.get("recommendations", {}).get("priority_score", 0),
                "performance_targets": optimization_report.get("recommendations", {}).get("performance_targets", {})
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get system optimization: {e}")
        raise HTTPException(status_code=500, detail=f"Optimization analysis error: {str(e)}")

@ai_router.post("/comprehensive-assessment")
async def run_comprehensive_assessment(background_tasks: BackgroundTasks, request_data: Dict[str, Any] = None):
    """Run comprehensive assessment using all AI agents"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        assessment_id = f"comprehensive-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Schedule comprehensive assessment in background
        background_tasks.add_task(run_comprehensive_background_assessment, assessment_id)
        
        return {
            "assessment_id": assessment_id,
            "status": "initiated",
            "message": "Comprehensive AI assessment started",
            "components": [
                "Security Vulnerability Scan",
                "Code Quality Analysis", 
                "Malware Detection",
                "System Optimization",
                "Performance Analysis"
            ],
            "estimated_duration": "5-10 minutes"
        }
        
    except Exception as e:
        logger.error(f"Failed to start comprehensive assessment: {e}")
        raise HTTPException(status_code=500, detail=f"Assessment error: {str(e)}")

async def run_comprehensive_background_assessment(assessment_id: str):
    """Background task for comprehensive assessment"""
    try:
        logger.info(f"Starting comprehensive assessment {assessment_id}")
        
        # Get comprehensive report from coordinator
        report = await coordinator.get_comprehensive_report()
        
        # Store results (in production, save to database)
        logger.info(f"Comprehensive assessment {assessment_id} completed: {report}")
        
    except Exception as e:
        logger.error(f"Comprehensive assessment {assessment_id} failed: {e}")

@ai_router.post("/code-quality-batch")
async def run_batch_code_analysis(request_data: Dict[str, Any]):
    """Run batch code quality assessment on multiple files"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        code_files = request_data.get('code_files', [])
        
        if not code_files:
            raise HTTPException(status_code=400, detail="Code files array is required")
        
        # Run code quality assessment using coordinator
        assessment_result = await coordinator.run_code_quality_assessment(code_files)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "batch_id": f"batch-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "total_files_processed": assessment_result.get("total_files", 0),
            "overall_quality_score": assessment_result.get("overall_quality_score", 0),
            "security_threats_found": assessment_result.get("security_threats", 0),
            "refactoring_summary": {
                "total_analyzed": len(assessment_result.get("refactoring_analysis", [])),
                "avg_maintainability": sum(r["maintainability_score"] for r in assessment_result.get("refactoring_analysis", [])) / max(1, len(assessment_result.get("refactoring_analysis", []))),
                "total_issues": sum(r["issues_count"] for r in assessment_result.get("refactoring_analysis", []))
            },
            "security_summary": {
                "total_scanned": len(assessment_result.get("malware_scans", [])),
                "malicious_files": len([s for s in assessment_result.get("malware_scans", []) if s["is_malicious"]]),
                "avg_risk_score": sum(s["risk_score"] for s in assessment_result.get("malware_scans", [])) / max(1, len(assessment_result.get("malware_scans", [])))
            },
            "optimization_insights": assessment_result.get("optimization_insights", {})
        }
        
    except Exception as e:
        logger.error(f"Failed to run batch code analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis error: {str(e)}")

@ai_router.get("/agent-reports")
async def get_all_agent_reports():
    """Get summary reports from all AI agents"""
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents not available")
    
    try:
        reports = {}
        
        # Code Refactoring Report
        try:
            refactoring_report = coordinator.agents["code_refactoring"].get_refactoring_report()
            reports["code_refactoring"] = refactoring_report
        except Exception as e:
            reports["code_refactoring"] = {"error": str(e)}
        
        # Malware Detection Report
        try:
            malware_report = coordinator.agents["malicious_code_detection"].get_detection_report()
            reports["malware_detection"] = malware_report
        except Exception as e:
            reports["malware_detection"] = {"error": str(e)}
        
        # System Optimization Analysis
        try:
            optimization_report = coordinator.agents["optimization"].run_comprehensive_analysis()
            reports["system_optimization"] = {
                "health_score": optimization_report.get("overall_health_score", 0),
                "system_cpu": optimization_report.get("system_metrics", {}).get("cpu", {}).get("usage_percent", 0),
                "system_memory": optimization_report.get("system_metrics", {}).get("memory", {}).get("percent", 0),
                "immediate_actions": len(optimization_report.get("recommendations", {}).get("immediate_actions", []))
            }
        except Exception as e:
            reports["system_optimization"] = {"error": str(e)}
        
        return {
            "timestamp": datetime.now().isoformat(),
            "reports": reports,
            "summary": {
                "agents_reporting": len([r for r in reports.values() if "error" not in r]),
                "agents_with_errors": len([r for r in reports.values() if "error" in r])
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get agent reports: {e}")
        raise HTTPException(status_code=500, detail=f"Agent reports error: {str(e)}")

# Health check for AI system
@ai_router.get("/health")
async def ai_health_check():
    """AI system health check"""
    return {
        "ai_agents_available": AI_AGENTS_AVAILABLE,
        "status": "healthy" if AI_AGENTS_AVAILABLE else "unavailable",
        "timestamp": datetime.now().isoformat(),
        "capabilities": [
            "CVE Monitoring",
            "Vulnerability Assessment", 
            "AI Decision Making",
            "Patch Management",
            "Agent Coordination",
            "Code Refactoring Analysis",
            "System Optimization",
            "Malicious Code Detection"
        ] if AI_AGENTS_AVAILABLE else []
    }