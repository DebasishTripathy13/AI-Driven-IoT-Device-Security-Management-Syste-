"""
AI Agent Coordinator System for IoT Security
Coordinates all AI agents: Monitoring, Patch Management, Decision Making, Optimization, and Evolution
Provides unified interface and orchestration for autonomous IoT security management
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

# Import all agents
from proactive_monitoring_agent import monitoring_agent, CVEData, DeviceVulnerability
from patch_validation_agent import patch_agent, PatchStatus, ValidationResult
from decision_making_agent import decision_agent, SecurityContext, RiskLevel, DecisionType
from code_refactoring_agent import CodeRefactoringAgent
from optimization_agent import OptimizationAgent
from malicious_code_detection_agent import MaliciousCodeDetectionAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SystemStatus:
    """Overall system status"""
    timestamp: str
    agents_active: Dict[str, bool]
    total_devices_monitored: int
    active_vulnerabilities: int
    pending_patches: int
    recent_decisions: int
    system_health: str

class AIAgentCoordinator:
    """
    Central coordinator for all AI security agents
    """
    
    def __init__(self):
        self.agents = {
            "monitoring": monitoring_agent,
            "patch_validation": patch_agent, 
            "decision_making": decision_agent,
            "code_refactoring": CodeRefactoringAgent(),
            "optimization": OptimizationAgent(),
            "malicious_code_detection": MaliciousCodeDetectionAgent()
        }
        
        self.coordination_rules = {
            "vulnerability_threshold": 8.0,
            "auto_patch_threshold": 7.0,
            "human_escalation_threshold": 9.0,
            "batch_processing_size": 10,
            "coordination_interval": 300  # 5 minutes
        }
        
    async def run_full_security_cycle(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run complete security assessment and response cycle"""
        logger.info(f"Starting full security cycle for {len(devices)} devices")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_devices": len(devices),
            "vulnerabilities_found": 0,
            "patches_applied": 0,
            "decisions_made": 0,
            "escalations": 0,
            "processing_time": 0
        }
        
        start_time = datetime.now()
        
        try:
            # Phase 1: Proactive Monitoring - Fetch CVEs and assess vulnerabilities
            logger.info("Phase 1: Vulnerability Assessment")
            cves = await self.agents["monitoring"].fetch_cve_data(days_back=7)
            vulnerability_assessments = await self.agents["monitoring"].assess_device_vulnerabilities(devices)
            
            results["vulnerabilities_found"] = len(vulnerability_assessments)
            
            # Phase 2: For each vulnerable device, make security decisions
            logger.info("Phase 2: Security Decision Making")
            for assessment in vulnerability_assessments:
                if assessment.risk_score >= self.coordination_rules["vulnerability_threshold"]:
                    # Create security context
                    security_context = SecurityContext(
                        device_id=assessment.device_id,
                        device_type=assessment.device_type,
                        device_criticality="high" if "medical" in assessment.device_type.lower() else "standard",
                        current_threat_level=RiskLevel.HIGH if assessment.risk_score >= 8.0 else RiskLevel.MEDIUM,
                        vulnerability_score=assessment.risk_score,
                        patch_urgency="critical" if assessment.risk_score >= 9.0 else "high",
                        business_impact="high",
                        historical_stability=0.85,
                        network_exposure="internal",
                        compliance_requirements=["ISO27001"],
                        operational_window={"maintenance_hours": "02:00-04:00"},
                        recent_incidents=[]
                    )
                    
                    # Make decision
                    decision = await self.agents["decision_making"].make_security_decision(
                        security_context=security_context,
                        patch_info={
                            "severity": "CRITICAL" if assessment.risk_score >= 9.0 else "HIGH",
                            "description": f"Security patches for {len(assessment.cve_matches)} vulnerabilities"
                        }
                    )
                    
                    results["decisions_made"] += 1
                    
                    # Phase 3: Execute decisions
                    if decision.decision_type == DecisionType.APPLY_IMMEDIATELY:
                        # Discover and apply patches
                        device_info = next((d for d in devices if d.get('deviceId') == assessment.device_id), None)
                        if device_info:
                            patches = await self.agents["patch_validation"].discover_available_patches(device_info)
                            if patches:
                                # Create test environment and deploy
                                test_env = await self.agents["patch_validation"].create_ephemeral_test_environment(device_info)
                                deployment_id = await self.agents["patch_validation"].deploy_patch(
                                    assessment.device_id, patches[0].patch_id, test_env
                                )
                                results["patches_applied"] += 1
                                
                                # Cleanup test environment
                                if test_env:
                                    await self.agents["patch_validation"].cleanup_test_environment(test_env)
                    
                    elif decision.decision_type == DecisionType.ESCALATE_HUMAN:
                        results["escalations"] += 1
                        logger.info(f"Escalating device {assessment.device_id} to human analyst")
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            results["processing_time"] = processing_time
            
            logger.info(f"Security cycle completed in {processing_time:.2f} seconds")
            logger.info(f"Results: {results['vulnerabilities_found']} vulnerabilities, {results['patches_applied']} patches applied, {results['escalations']} escalations")
            
        except Exception as e:
            logger.error(f"Error in security cycle: {e}")
            results["error"] = str(e)
        
        return results
    
    async def run_code_quality_assessment(self, code_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run comprehensive code quality and security assessment"""
        logger.info(f"Starting code quality assessment for {len(code_files)} files")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_files": len(code_files),
            "refactoring_analysis": [],
            "malware_scans": [],
            "optimization_insights": {},
            "overall_quality_score": 0,
            "security_threats": 0
        }
        
        try:
            # Code Refactoring Analysis
            for file_info in code_files:
                if 'content' in file_info and 'file_type' in file_info:
                    refactoring_result = self.agents["code_refactoring"].analyze_code_quality(
                        file_info['content'], 
                        file_info['file_type'], 
                        file_info.get('context', '')
                    )
                    results["refactoring_analysis"].append({
                        "file": file_info.get('name', 'unknown'),
                        "maintainability_score": refactoring_result.get('maintainability_score', 0),
                        "issues_count": len(refactoring_result.get('issues', [])),
                        "suggestions_count": len(refactoring_result.get('suggestions', []))
                    })
                    
                    # Malicious Code Detection
                    malware_result = self.agents["malicious_code_detection"].scan_code_content(
                        file_info['content'],
                        file_info['file_type'],
                        file_info.get('context', '')
                    )
                    results["malware_scans"].append({
                        "file": file_info.get('name', 'unknown'),
                        "risk_score": malware_result.get('risk_score', 0),
                        "is_malicious": malware_result.get('is_malicious', False),
                        "threat_level": malware_result.get('ai_analysis', {}).get('threat_level', 'none')
                    })
                    
                    if malware_result.get('is_malicious', False):
                        results["security_threats"] += 1
            
            # System Optimization Analysis
            optimization_report = self.agents["optimization"].run_comprehensive_analysis()
            results["optimization_insights"] = {
                "health_score": optimization_report.get('overall_health_score', 0),
                "cpu_usage": optimization_report.get('system_metrics', {}).get('cpu', {}).get('usage_percent', 0),
                "memory_usage": optimization_report.get('system_metrics', {}).get('memory', {}).get('percent', 0),
                "recommendations_count": len(optimization_report.get('recommendations', {}).get('immediate_actions', []))
            }
            
            # Calculate overall quality score
            if results["refactoring_analysis"]:
                avg_maintainability = sum(r["maintainability_score"] for r in results["refactoring_analysis"]) / len(results["refactoring_analysis"])
                security_penalty = results["security_threats"] * 20  # Penalty for malicious files
                optimization_bonus = results["optimization_insights"]["health_score"] / 10
                
                results["overall_quality_score"] = max(0, min(100, avg_maintainability + optimization_bonus - security_penalty))
            
            logger.info(f"Code quality assessment completed. Overall score: {results['overall_quality_score']}")
            
        except Exception as e:
            logger.error(f"Error in code quality assessment: {e}")
            results["error"] = str(e)
        
        return results
    
    async def run_security_hardening_cycle(self, target_systems: List[str]) -> Dict[str, Any]:
        """Run comprehensive security hardening using all security agents"""
        logger.info(f"Starting security hardening for {len(target_systems)} systems")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target_systems": target_systems,
            "optimization_applied": 0,
            "vulnerabilities_patched": 0,
            "malware_detected": 0,
            "code_refactored": 0,
            "overall_security_improvement": 0
        }
        
        start_time = datetime.now()
        
        try:
            # Phase 1: System Optimization
            logger.info("Phase 1: System Optimization Analysis")
            optimization_report = self.agents["optimization"].run_comprehensive_analysis()
            
            # Apply immediate optimizations (simulated)
            immediate_actions = optimization_report.get('recommendations', {}).get('immediate_actions', [])
            high_impact_actions = [action for action in immediate_actions if action.get('impact') == 'high']
            results["optimization_applied"] = len(high_impact_actions)
            
            # Phase 2: Code Security Scanning
            logger.info("Phase 2: Malicious Code Detection")
            for system in target_systems:
                # Simulate scanning system files
                try:
                    if Path(system).exists():
                        scan_result = self.agents["malicious_code_detection"].scan_file(system)
                        if scan_result.get('is_malicious', False):
                            results["malware_detected"] += 1
                            logger.warning(f"Malicious code detected in {system}")
                except Exception:
                    # Handle file scanning errors gracefully
                    pass
            
            # Phase 3: Code Quality Improvement
            logger.info("Phase 3: Code Refactoring Analysis")
            refactoring_report = self.agents["code_refactoring"].get_refactoring_report()
            results["code_refactored"] = refactoring_report.get("total_analyses", 0)
            
            # Calculate overall security improvement
            base_score = 60  # Starting security baseline
            optimization_improvement = min(20, results["optimization_applied"] * 2)
            malware_penalty = results["malware_detected"] * 15
            refactoring_bonus = min(15, results["code_refactored"] * 3)
            
            results["overall_security_improvement"] = max(0, base_score + optimization_improvement + refactoring_bonus - malware_penalty)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            results["processing_time"] = processing_time
            
            logger.info(f"Security hardening completed in {processing_time:.2f} seconds")
            logger.info(f"Security improvement score: {results['overall_security_improvement']}")
            
        except Exception as e:
            logger.error(f"Error in security hardening cycle: {e}")
            results["error"] = str(e)
        
        return results
    
    async def get_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive system report using all agents"""
        try:
            report = {
                "timestamp": datetime.now().isoformat(),
                "system_overview": {},
                "security_status": {},
                "optimization_status": {},
                "code_quality_status": {},
                "threat_detection_status": {},
                "recommendations": []
            }
            
            # Get system status
            system_status = await self.get_system_status()
            report["system_overview"] = {
                "agents_active": system_status.agents_active,
                "system_health": system_status.system_health,
                "devices_monitored": system_status.total_devices_monitored,
                "active_vulnerabilities": system_status.active_vulnerabilities
            }
            
            # Get optimization insights
            optimization_report = self.agents["optimization"].run_comprehensive_analysis()
            report["optimization_status"] = {
                "health_score": optimization_report.get('overall_health_score', 0),
                "immediate_actions_needed": len(optimization_report.get('recommendations', {}).get('immediate_actions', [])),
                "system_cpu": optimization_report.get('system_metrics', {}).get('cpu', {}).get('usage_percent', 0),
                "system_memory": optimization_report.get('system_metrics', {}).get('memory', {}).get('percent', 0)
            }
            
            # Get code quality insights
            refactoring_report = self.agents["code_refactoring"].get_refactoring_report()
            report["code_quality_status"] = {
                "total_analyses": refactoring_report.get("total_analyses", 0),
                "average_maintainability": refactoring_report.get("average_maintainability_score", 0),
                "total_issues": refactoring_report.get("total_issues_found", 0)
            }
            
            # Get threat detection insights
            detection_report = self.agents["malicious_code_detection"].get_detection_report()
            report["threat_detection_status"] = {
                "total_scans": detection_report.get("total_scans", 0),
                "malicious_detections": detection_report.get("malicious_detections", 0),
                "average_risk_score": detection_report.get("average_risk_score", 0)
            }
            
            # Generate unified recommendations
            recommendations = []
            
            # Optimization recommendations
            if report["optimization_status"]["health_score"] < 70:
                recommendations.append("PRIORITY: System optimization needed - health score below threshold")
            
            # Security recommendations
            if report["threat_detection_status"]["malicious_detections"] > 0:
                recommendations.append("CRITICAL: Malicious code detected - immediate investigation required")
            
            # Code quality recommendations
            if report["code_quality_status"]["average_maintainability"] < 6:
                recommendations.append("IMPROVEMENT: Code refactoring needed - maintainability below standards")
            
            # General recommendations
            if report["system_overview"]["active_vulnerabilities"] > 5:
                recommendations.append("SECURITY: High number of vulnerabilities - patch management needed")
            
            if not recommendations:
                recommendations.append("GOOD: All systems operating within acceptable parameters")
            
            report["recommendations"] = recommendations
            
            logger.info("Comprehensive report generated successfully")
            return report
            
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "recommendations": ["Check system logs for detailed error information"]
            }
    
    async def get_system_status(self) -> SystemStatus:
        """Get overall system status"""
        try:
            # Check agent health
            agents_active = {}
            for name, agent in self.agents.items():
                # Simple health check - in production would be more sophisticated
                agents_active[name] = True
            
            # Get metrics (simulated for demo)
            return SystemStatus(
                timestamp=datetime.now().isoformat(),
                agents_active=agents_active,
                total_devices_monitored=25,
                active_vulnerabilities=7,
                pending_patches=3,
                recent_decisions=12,
                system_health="HEALTHY"
            )
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return SystemStatus(
                timestamp=datetime.now().isoformat(),
                agents_active={name: False for name in self.agents.keys()},
                total_devices_monitored=0,
                active_vulnerabilities=0,
                pending_patches=0,
                recent_decisions=0,
                system_health="ERROR"
            )

# Global coordinator instance
coordinator = AIAgentCoordinator()

async def demo_ai_security_system():
    """Demonstrate the complete AI security system"""
    print("🤖 AI-Powered IoT Security System Demo")
    print("=" * 50)
    
    # Sample IoT devices
    demo_devices = [
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
    
    print(f"🔍 Monitoring {len(demo_devices)} IoT devices...")
    
    # Get system status
    status = await coordinator.get_system_status()
    print(f"📊 System Status: {status.system_health}")
    print(f"   Active Agents: {sum(status.agents_active.values())}/{len(status.agents_active)}")
    
    # Run full security cycle
    print("\n🚀 Running Complete AI Security Cycle...")
    results = await coordinator.run_full_security_cycle(demo_devices)
    
    print("\n📈 Security Cycle Results:")
    print(f"   • Devices Processed: {results['total_devices']}")
    print(f"   • Vulnerabilities Found: {results['vulnerabilities_found']}")
    print(f"   • Security Decisions Made: {results['decisions_made']}")
    print(f"   • Patches Applied: {results['patches_applied']}")
    print(f"   • Human Escalations: {results['escalations']}")
    print(f"   • Processing Time: {results['processing_time']:.2f} seconds")
    
    if results.get('error'):
        print(f"   ⚠️  Error: {results['error']}")
    
    print("\n✅ AI Security System Demo Complete!")
    print("\n🎯 Key Features Demonstrated:")
    print("   1. 🔍 Proactive Monitoring - CVE fetching and vulnerability assessment")
    print("   2. 🛠️  Patch & Validation - Automated patch deployment with testing")
    print("   3. 🧠 Decision Making - AI-powered security decision engine")
    print("   4. 🤝 Agent Coordination - Unified orchestration of all agents")
    
    return results

if __name__ == "__main__":
    asyncio.run(demo_ai_security_system())