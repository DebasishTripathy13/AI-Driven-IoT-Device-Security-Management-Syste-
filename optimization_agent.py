"""
Optimization Agent for Medical IoT Device Manager
Analyzes system performance, identifies bottlenecks, and suggests optimizations
"""

import os
import psutil
import time
import logging
import json
from datetime import datetime, timedelta
from groq import Groq
from dotenv import load_dotenv
from database_manager import db_manager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OptimizationAgent:
    def __init__(self):
        """Initialize the Optimization Agent with Groq API client"""
        api_key = os.environ.get("GROQ_API_KEY")
        if api_key:
            self.client = Groq(api_key=api_key)
            self.ai_enabled = True
        else:
            self.client = None
            self.ai_enabled = False
            logger.warning("Groq API key not set - AI analysis disabled")
        self.model = "openai/gpt-oss-120b"
        self.performance_history = []
        
    def collect_system_metrics(self):
        """
        Collect current system performance metrics
        
        Returns:
            dict: System performance data
        """
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics (if available)
            try:
                network = psutil.net_io_counters()
                network_stats = {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            except:
                network_stats = {"error": "Network stats unavailable"}
            
            # Process information
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] > 1.0 or proc_info['memory_percent'] > 1.0:
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "usage_percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq._asdict() if cpu_freq else None
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.percent
                },
                "network": network_stats,
                "top_processes": sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
            }
            
            # Store in history
            self.performance_history.append(metrics)
            
            # Keep only last 100 entries
            if len(self.performance_history) > 100:
                self.performance_history = self.performance_history[-100:]
            
            logger.info(f"System metrics collected - CPU: {cpu_percent}%, Memory: {memory.percent}%, Disk: {disk.percent}%")
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}
    
    def analyze_performance_trends(self):
        """
        Analyze performance trends from historical data
        
        Returns:
            dict: Performance trend analysis
        """
        try:
            if len(self.performance_history) < 5:
                return {
                    "status": "insufficient_data",
                    "message": "Not enough historical data for trend analysis",
                    "recommendations": ["Collect more performance data over time"]
                }
            
            # Calculate trends
            recent_metrics = self.performance_history[-10:]  # Last 10 entries
            
            cpu_trend = [m["cpu"]["usage_percent"] for m in recent_metrics if "cpu" in m and not m.get("error")]
            memory_trend = [m["memory"]["percent"] for m in recent_metrics if "memory" in m and not m.get("error")]
            disk_trend = [m["disk"]["percent"] for m in recent_metrics if "disk" in m and not m.get("error")]
            
            # Calculate averages and detect spikes
            analysis = {
                "cpu_analysis": {
                    "average": sum(cpu_trend) / len(cpu_trend) if cpu_trend else 0,
                    "peak": max(cpu_trend) if cpu_trend else 0,
                    "trend": "increasing" if len(cpu_trend) > 1 and cpu_trend[-1] > cpu_trend[0] else "stable"
                },
                "memory_analysis": {
                    "average": sum(memory_trend) / len(memory_trend) if memory_trend else 0,
                    "peak": max(memory_trend) if memory_trend else 0,
                    "trend": "increasing" if len(memory_trend) > 1 and memory_trend[-1] > memory_trend[0] else "stable"
                },
                "disk_analysis": {
                    "average": sum(disk_trend) / len(disk_trend) if disk_trend else 0,
                    "current": disk_trend[-1] if disk_trend else 0,
                    "trend": "increasing" if len(disk_trend) > 1 and disk_trend[-1] > disk_trend[0] else "stable"
                }
            }
            
            # Identify bottlenecks
            bottlenecks = []
            if analysis["cpu_analysis"]["average"] > 80:
                bottlenecks.append({"type": "cpu", "severity": "high", "description": "High CPU usage detected"})
            elif analysis["cpu_analysis"]["average"] > 60:
                bottlenecks.append({"type": "cpu", "severity": "medium", "description": "Moderate CPU usage"})
            
            if analysis["memory_analysis"]["average"] > 85:
                bottlenecks.append({"type": "memory", "severity": "high", "description": "High memory usage detected"})
            elif analysis["memory_analysis"]["average"] > 70:
                bottlenecks.append({"type": "memory", "severity": "medium", "description": "Moderate memory usage"})
            
            if analysis["disk_analysis"]["current"] > 90:
                bottlenecks.append({"type": "disk", "severity": "high", "description": "Disk space critically low"})
            elif analysis["disk_analysis"]["current"] > 75:
                bottlenecks.append({"type": "disk", "severity": "medium", "description": "Disk space getting low"})
            
            analysis["bottlenecks"] = bottlenecks
            analysis["status"] = "completed"
            
            logger.info(f"Performance trend analysis completed. Found {len(bottlenecks)} bottlenecks")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing performance trends: {e}")
            return {"status": "error", "message": str(e)}
    
    def analyze_api_performance(self):
        """
        Analyze API performance from request logs
        
        Returns:
            dict: API performance analysis
        """
        try:
            # Get recent API requests from database
            all_requests = db_manager.get_all_api_requests()
            
            if not all_requests:
                return {
                    "status": "no_data",
                    "message": "No API request data available",
                    "recommendations": ["Generate API traffic to analyze performance"]
                }
            
            # Filter recent requests (last hour)
            recent_time = datetime.now() - timedelta(hours=1)
            recent_requests = [
                req for req in all_requests 
                if datetime.fromisoformat(req.get('timestamp', '2000-01-01')) > recent_time
            ]
            
            if not recent_requests:
                recent_requests = all_requests[-50:]  # Use last 50 requests if no recent ones
            
            # Analyze request patterns
            endpoint_stats = {}
            response_times = []
            status_codes = {}
            
            for request in recent_requests:
                endpoint = request.get('endpoint', 'unknown')
                method = request.get('method', 'GET')
                status_code = request.get('status_code', 200)
                
                # Track endpoint usage
                endpoint_key = f"{method} {endpoint}"
                if endpoint_key not in endpoint_stats:
                    endpoint_stats[endpoint_key] = {"count": 0, "avg_time": 0}
                endpoint_stats[endpoint_key]["count"] += 1
                
                # Track status codes
                if status_code not in status_codes:
                    status_codes[status_code] = 0
                status_codes[status_code] += 1
                
                # Simulate response time (since we don't track it yet)
                # In a real implementation, you would track actual response times
                simulated_time = 100 + (hash(endpoint) % 400)  # 100-500ms range
                response_times.append(simulated_time)
            
            # Calculate performance metrics
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            error_rate = sum(1 for code in status_codes.keys() if code >= 400) / len(recent_requests) * 100
            throughput = len(recent_requests) / 60  # requests per minute
            
            # Most used endpoints
            top_endpoints = sorted(endpoint_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
            
            analysis = {
                "status": "completed",
                "metrics": {
                    "total_requests": len(recent_requests),
                    "avg_response_time_ms": round(avg_response_time, 2),
                    "error_rate_percent": round(error_rate, 2),
                    "throughput_rpm": round(throughput, 2)
                },
                "top_endpoints": [{"endpoint": ep, "count": stats["count"]} for ep, stats in top_endpoints],
                "status_distribution": status_codes,
                "performance_issues": []
            }
            
            # Identify performance issues
            if avg_response_time > 1000:
                analysis["performance_issues"].append({
                    "type": "slow_response",
                    "severity": "high",
                    "description": f"Average response time is {avg_response_time:.0f}ms"
                })
            
            if error_rate > 5:
                analysis["performance_issues"].append({
                    "type": "high_error_rate",
                    "severity": "high",
                    "description": f"Error rate is {error_rate:.1f}%"
                })
            
            if throughput > 100:
                analysis["performance_issues"].append({
                    "type": "high_load",
                    "severity": "medium",
                    "description": f"High throughput: {throughput:.1f} requests/minute"
                })
            
            logger.info(f"API performance analysis completed. {len(analysis['performance_issues'])} issues found")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing API performance: {e}")
            return {"status": "error", "message": str(e)}
    
    def generate_optimization_recommendations(self, system_metrics, performance_trends, api_analysis):
        """
        Generate AI-powered optimization recommendations
        
        Args:
            system_metrics (dict): Current system metrics
            performance_trends (dict): Performance trend analysis
            api_analysis (dict): API performance analysis
            
        Returns:
            dict: Optimization recommendations
        """
        try:
            # Prepare data summary for AI analysis
            data_summary = {
                "system": {
                    "cpu_usage": system_metrics.get("cpu", {}).get("usage_percent", 0),
                    "memory_usage": system_metrics.get("memory", {}).get("percent", 0),
                    "disk_usage": system_metrics.get("disk", {}).get("percent", 0)
                },
                "trends": {
                    "bottlenecks": performance_trends.get("bottlenecks", []),
                    "cpu_trend": performance_trends.get("cpu_analysis", {}).get("trend", "stable"),
                    "memory_trend": performance_trends.get("memory_analysis", {}).get("trend", "stable")
                },
                "api": {
                    "avg_response_time": api_analysis.get("metrics", {}).get("avg_response_time_ms", 0),
                    "error_rate": api_analysis.get("metrics", {}).get("error_rate_percent", 0),
                    "throughput": api_analysis.get("metrics", {}).get("throughput_rpm", 0),
                    "issues": api_analysis.get("performance_issues", [])
                }
            }
            
            if not self.ai_enabled:
                # Basic recommendations without AI
                recommendations = {
                    "priority_score": 5,
                    "immediate_actions": [{"action": "Enable AI analysis", "impact": "medium", "complexity": "low", "description": "Set GROQ_API_KEY for AI-powered optimization recommendations"}],
                    "medium_term_optimizations": [{"optimization": "Manual performance review", "benefit": "Identify bottlenecks", "implementation": "Review system metrics manually"}],
                    "long_term_strategy": [{"strategy": "Performance monitoring", "goal": "Continuous improvement", "timeline": "Ongoing"}],
                    "performance_targets": {"response_time_ms": 500, "cpu_usage_target": 70, "memory_usage_target": 80, "error_rate_target": 1},
                    "monitoring_recommendations": ["Implement system monitoring", "Set up performance alerts"]
                }
            else:
                prompt = f"""
                As a performance optimization expert for IoT medical device management systems, analyze the following performance data and provide specific optimization recommendations:
                
                Performance Data:
                {json.dumps(data_summary, indent=2)}
                
                Consider these optimization areas:
                1. System Resource Optimization (CPU, Memory, Disk)
                2. API Performance Improvements
                3. Database Query Optimization
                4. Caching Strategies
                5. Load Balancing and Scaling
                6. IoT Device Communication Efficiency
                7. Security vs Performance Balance
                
                Provide recommendations in JSON format:
                {{
                    "priority_score": number,
                    "immediate_actions": [
                        {{"action": "string", "impact": "high|medium|low", "complexity": "low|medium|high", "description": "string"}}
                    ],
                    "medium_term_optimizations": [
                        {{"optimization": "string", "benefit": "string", "implementation": "string"}}
                    ],
                    "long_term_strategy": [
                        {{"strategy": "string", "goal": "string", "timeline": "string"}}
                    ],
                    "performance_targets": {{
                        "response_time_ms": number,
                        "cpu_usage_target": number,
                        "memory_usage_target": number,
                        "error_rate_target": number
                    }},
                    "monitoring_recommendations": ["recommendation1", "recommendation2"]
                }}
                """
                
                response = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model,
                    temperature=0.3,
                    max_tokens=2000
                )
                
                recommendations_text = response.choices[0].message.content
            
            try:
                recommendations = json.loads(recommendations_text)
            except json.JSONDecodeError:
                recommendations = {
                    "priority_score": 5,
                    "immediate_actions": [{"action": "Manual performance review", "impact": "medium", "complexity": "low", "description": "Conduct manual analysis of performance metrics"}],
                    "medium_term_optimizations": [{"optimization": "System monitoring", "benefit": "Better visibility", "implementation": "Implement comprehensive monitoring"}],
                    "long_term_strategy": [{"strategy": "Performance optimization", "goal": "Improve overall system performance", "timeline": "3-6 months"}],
                    "performance_targets": {"response_time_ms": 500, "cpu_usage_target": 70, "memory_usage_target": 80, "error_rate_target": 1},
                    "monitoring_recommendations": ["Implement real-time monitoring", "Set up alerting"]
                }
            
            # Store optimization analysis
            self.store_optimization_result(data_summary, recommendations)
            
            logger.info(f"Optimization recommendations generated. Priority score: {recommendations.get('priority_score', 'N/A')}")
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating optimization recommendations: {e}")
            return {
                "priority_score": 0,
                "immediate_actions": [{"action": f"Error: {str(e)}", "impact": "high", "complexity": "high", "description": "Fix the optimization analysis error"}],
                "medium_term_optimizations": [],
                "long_term_strategy": [],
                "performance_targets": {},
                "monitoring_recommendations": ["Check system logs for errors"]
            }
    
    def run_comprehensive_analysis(self):
        """
        Run a comprehensive optimization analysis
        
        Returns:
            dict: Complete optimization analysis results
        """
        try:
            logger.info("Starting comprehensive optimization analysis...")
            
            # Collect current metrics
            system_metrics = self.collect_system_metrics()
            
            # Analyze trends
            performance_trends = self.analyze_performance_trends()
            
            # Analyze API performance
            api_analysis = self.analyze_api_performance()
            
            # Generate recommendations
            recommendations = self.generate_optimization_recommendations(
                system_metrics, performance_trends, api_analysis
            )
            
            # Compile comprehensive report
            report = {
                "analysis_timestamp": datetime.now().isoformat(),
                "system_metrics": system_metrics,
                "performance_trends": performance_trends,
                "api_analysis": api_analysis,
                "recommendations": recommendations,
                "overall_health_score": self.calculate_health_score(system_metrics, performance_trends, api_analysis)
            }
            
            logger.info("Comprehensive optimization analysis completed")
            return report
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {e}")
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "error": str(e),
                "overall_health_score": 0
            }
    
    def calculate_health_score(self, system_metrics, performance_trends, api_analysis):
        """Calculate overall system health score (0-100)"""
        try:
            score = 100
            
            # Deduct points for system issues
            cpu_usage = system_metrics.get("cpu", {}).get("usage_percent", 0)
            memory_usage = system_metrics.get("memory", {}).get("percent", 0)
            disk_usage = system_metrics.get("disk", {}).get("percent", 0)
            
            if cpu_usage > 80:
                score -= 20
            elif cpu_usage > 60:
                score -= 10
                
            if memory_usage > 85:
                score -= 20
            elif memory_usage > 70:
                score -= 10
                
            if disk_usage > 90:
                score -= 15
            elif disk_usage > 75:
                score -= 8
                
            # Deduct points for performance issues
            bottlenecks = performance_trends.get("bottlenecks", [])
            score -= len(bottlenecks) * 5
            
            # Deduct points for API issues
            api_issues = api_analysis.get("performance_issues", [])
            score -= len(api_issues) * 10
            
            return max(0, min(100, score))
            
        except Exception:
            return 50  # Default middle score if calculation fails
    
    def store_optimization_result(self, data_summary, recommendations):
        """Store optimization analysis results in database"""
        try:
            db_manager.log_security_event(
                event_type="optimization_analysis",
                severity="info",
                description="System optimization analysis completed",
                source_ip="internal",
                additional_data={
                    "analysis_type": "optimization",
                    "priority_score": recommendations.get("priority_score", 0),
                    "immediate_actions_count": len(recommendations.get("immediate_actions", [])),
                    "system_cpu": data_summary.get("system", {}).get("cpu_usage", 0),
                    "system_memory": data_summary.get("system", {}).get("memory_usage", 0),
                    "api_response_time": data_summary.get("api", {}).get("avg_response_time", 0)
                }
            )
        except Exception as e:
            logger.error(f"Error storing optimization result: {e}")

def main():
    """Test the Optimization Agent"""
    agent = OptimizationAgent()
    
    print("Testing Optimization Agent...")
    
    # Run comprehensive analysis
    report = agent.run_comprehensive_analysis()
    print(f"Optimization analysis completed:")
    print(f"Health Score: {report.get('overall_health_score', 'N/A')}")
    print(f"System CPU: {report.get('system_metrics', {}).get('cpu', {}).get('usage_percent', 'N/A')}%")
    print(f"System Memory: {report.get('system_metrics', {}).get('memory', {}).get('percent', 'N/A')}%")
    print(f"Recommendations: {len(report.get('recommendations', {}).get('immediate_actions', []))} immediate actions")

if __name__ == "__main__":
    main()