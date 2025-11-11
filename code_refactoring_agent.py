"""
Code Refactoring Agent for Medical IoT Device Manager
Analyzes code quality, suggests refactoring improvements, and maintains code standards
"""

import os
import logging
import json
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv
from database_manager import db_manager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CodeRefactoringAgent:
    def __init__(self):
        """Initialize the Code Refactoring Agent with Groq API client"""
        api_key = os.environ.get("GROQ_API_KEY")
        if api_key:
            self.client = Groq(api_key=api_key)
            self.ai_enabled = True
        else:
            self.client = None
            self.ai_enabled = False
            logger.warning("Groq API key not set - AI analysis disabled")
        self.model = "openai/gpt-oss-120b"
        
    def analyze_code_quality(self, code_snippet, file_type="python", context=""):
        """
        Analyze code quality and suggest refactoring improvements
        
        Args:
            code_snippet (str): The code to analyze
            file_type (str): The type of code (python, javascript, etc.)
            context (str): Additional context about the code's purpose
            
        Returns:
            dict: Analysis results with suggestions
        """
        try:
            if not self.ai_enabled:
                # Basic analysis without AI
                analysis = {
                    "maintainability_score": 6,  # Default score
                    "issues": [{"type": "ai_disabled", "severity": "low", "description": "AI analysis disabled - Groq API key not available", "line_reference": "N/A"}],
                    "suggestions": [{"category": "general", "description": "Enable AI analysis by setting GROQ_API_KEY environment variable", "example": "", "priority": "low"}],
                    "overall_assessment": "Basic analysis completed - AI features disabled"
                }
            else:
                prompt = f"""
                As a senior software engineer and code quality expert, analyze the following {file_type} code for:
                
                1. Code Quality Issues:
                   - Code smells and anti-patterns
                   - Complexity and readability issues
                   - Performance bottlenecks
                   - Security vulnerabilities
                
                2. Refactoring Suggestions:
                   - Specific improvements with examples
                   - Design pattern recommendations
                   - Code organization suggestions
                   - Best practices alignment
                
                3. Maintainability Score (1-10):
                   - Rate the code's maintainability
                   - Justify the score
                
                Context: {context}
                
                Code to analyze:
                ```{file_type}
                {code_snippet}
                ```
                
                Provide your analysis in JSON format with the following structure:
                {{
                    "maintainability_score": number,
                    "issues": [
                        {{"type": "string", "severity": "high|medium|low", "description": "string", "line_reference": "string"}}
                    ],
                    "suggestions": [
                        {{"category": "string", "description": "string", "example": "string", "priority": "high|medium|low"}}
                    ],
                    "overall_assessment": "string"
                }}
                """
                
                response = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model,
                    temperature=0.3,
                    max_tokens=2000
                )
                
                analysis_text = response.choices[0].message.content
            
            # Try to parse JSON response
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                # If JSON parsing fails, create a structured response
                analysis = {
                    "maintainability_score": 5,
                    "issues": [{"type": "parsing_error", "severity": "low", "description": "Could not parse detailed analysis", "line_reference": "N/A"}],
                    "suggestions": [{"category": "general", "description": analysis_text[:500], "example": "", "priority": "medium"}],
                    "overall_assessment": "Analysis completed but format parsing failed"
                }
            
            # Store analysis in database
            self.store_analysis_result(code_snippet, file_type, analysis)
            
            logger.info(f"Code analysis completed. Maintainability score: {analysis.get('maintainability_score', 'N/A')}")
            return analysis
            
        except Exception as e:
            logger.error(f"Error in code quality analysis: {e}")
            return {
                "maintainability_score": 0,
                "issues": [{"type": "error", "severity": "high", "description": str(e), "line_reference": "N/A"}],
                "suggestions": [],
                "overall_assessment": f"Analysis failed: {str(e)}"
            }
    
    def suggest_refactoring_patterns(self, code_snippet, file_type="python", target_patterns=None):
        """
        Suggest specific design patterns and refactoring approaches
        
        Args:
            code_snippet (str): The code to analyze
            file_type (str): The type of code
            target_patterns (list): Specific patterns to focus on
            
        Returns:
            dict: Pattern-specific suggestions
        """
        try:
            patterns_focus = target_patterns or ["singleton", "factory", "observer", "strategy", "decorator"]
            
            if not self.ai_enabled:
                # Basic suggestions without AI
                suggestions = {
                    "applicable_patterns": [{"pattern_name": "manual_review", "benefit": "Enable AI for pattern analysis", "implementation_example": "Set GROQ_API_KEY environment variable", "impact": "high"}],
                    "refactoring_roadmap": ["Enable AI analysis", "Conduct manual code review", "Apply basic refactoring"],
                    "estimated_effort": "medium"
                }
            else:
                prompt = f"""
                As a software architecture expert, analyze this {file_type} code and suggest specific design pattern implementations:
                
                Focus on these patterns: {', '.join(patterns_focus)}
                
                For each applicable pattern:
                1. Explain why it would benefit this code
                2. Provide a concrete implementation example
                3. Highlight the improvements it would bring
                
                Code:
                ```{file_type}
                {code_snippet}
                ```
                
                Respond in JSON format:
                {{
                    "applicable_patterns": [
                        {{
                            "pattern_name": "string",
                            "benefit": "string",
                            "implementation_example": "string",
                            "impact": "high|medium|low"
                        }}
                    ],
                    "refactoring_roadmap": ["step1", "step2", "step3"],
                    "estimated_effort": "low|medium|high"
                }}
                """
                
                response = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model,
                    temperature=0.3,
                    max_tokens=2000
                )
                
                suggestions_text = response.choices[0].message.content
            
            try:
                suggestions = json.loads(suggestions_text)
            except json.JSONDecodeError:
                suggestions = {
                    "applicable_patterns": [],
                    "refactoring_roadmap": ["Manual review required"],
                    "estimated_effort": "medium"
                }
            
            logger.info(f"Pattern analysis completed. Found {len(suggestions.get('applicable_patterns', []))} applicable patterns")
            return suggestions
            
        except Exception as e:
            logger.error(f"Error in pattern analysis: {e}")
            return {
                "applicable_patterns": [],
                "refactoring_roadmap": [f"Error occurred: {str(e)}"],
                "estimated_effort": "high"
            }
    
    def analyze_project_structure(self, project_path):
        """
        Analyze overall project structure and suggest architectural improvements
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            dict: Project structure analysis
        """
        try:
            # Get project file structure
            files_info = []
            for root, dirs, files in os.walk(project_path):
                for file in files:
                    if file.endswith(('.py', '.js', '.ts', '.json')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                files_info.append({
                                    "path": file_path,
                                    "type": file.split('.')[-1],
                                    "size": len(content),
                                    "lines": len(content.split('\n'))
                                })
                        except Exception:
                            continue
            
            # Create structure summary
            structure_summary = {
                "total_files": len(files_info),
                "file_types": {},
                "large_files": [],
                "project_metrics": {
                    "total_lines": sum(f["lines"] for f in files_info),
                    "average_file_size": sum(f["size"] for f in files_info) / len(files_info) if files_info else 0
                }
            }
            
            # Analyze file types
            for file_info in files_info:
                file_type = file_info["type"]
                if file_type not in structure_summary["file_types"]:
                    structure_summary["file_types"][file_type] = 0
                structure_summary["file_types"][file_type] += 1
                
                # Flag large files (> 500 lines)
                if file_info["lines"] > 500:
                    structure_summary["large_files"].append({
                        "path": file_info["path"],
                        "lines": file_info["lines"]
                    })
            
            prompt = f"""
            As a software architect, analyze this project structure and provide architectural recommendations:
            
            Project Metrics:
            {json.dumps(structure_summary, indent=2)}
            
            Provide recommendations for:
            1. Project organization improvements
            2. Module separation suggestions
            3. Dependency management
            4. Scalability considerations
            5. Maintenance improvements
            
            Respond in JSON format:
            {{
                "architecture_score": number,
                "recommendations": [
                    {{"category": "string", "description": "string", "priority": "high|medium|low"}}
                ],
                "refactoring_priorities": ["priority1", "priority2", "priority3"]
            }}
            """
            
            response = self.client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=self.model,
                temperature=0.3,
                max_tokens=1500
            )
            
            analysis_text = response.choices[0].message.content
            
            try:
                analysis = json.loads(analysis_text)
                analysis["project_metrics"] = structure_summary
            except json.JSONDecodeError:
                analysis = {
                    "architecture_score": 5,
                    "recommendations": [{"category": "general", "description": "Manual architectural review recommended", "priority": "medium"}],
                    "refactoring_priorities": ["Code organization", "Module separation", "Documentation"],
                    "project_metrics": structure_summary
                }
            
            logger.info(f"Project structure analysis completed. Architecture score: {analysis.get('architecture_score', 'N/A')}")
            return analysis
            
        except Exception as e:
            logger.error(f"Error in project structure analysis: {e}")
            return {
                "architecture_score": 0,
                "recommendations": [{"category": "error", "description": str(e), "priority": "high"}],
                "refactoring_priorities": [],
                "project_metrics": {}
            }
    
    def store_analysis_result(self, code_snippet, file_type, analysis):
        """Store code analysis results in database"""
        try:
            db_manager.log_security_event(
                event_type="code_analysis",
                severity="info",
                description=f"Code refactoring analysis completed for {file_type} code",
                source_ip="internal",
                additional_data={
                    "analysis_type": "refactoring",
                    "file_type": file_type,
                    "maintainability_score": analysis.get("maintainability_score", 0),
                    "issues_count": len(analysis.get("issues", [])),
                    "suggestions_count": len(analysis.get("suggestions", []))
                }
            )
        except Exception as e:
            logger.error(f"Error storing analysis result: {e}")
    
    def get_refactoring_report(self):
        """Generate a comprehensive refactoring report"""
        try:
            # Get recent analysis events
            all_events = db_manager.get_all_security_events()
            refactoring_events = [
                event for event in all_events 
                if event.get('event_type') == 'code_analysis' and 
                event.get('additional_data', {}).get('analysis_type') == 'refactoring'
            ]
            
            # Generate summary statistics
            total_analyses = len(refactoring_events)
            if total_analyses == 0:
                return {
                    "summary": "No refactoring analyses found",
                    "total_analyses": 0,
                    "recommendations": ["Run code analysis to generate refactoring insights"]
                }
            
            avg_maintainability = sum(
                event.get('additional_data', {}).get('maintainability_score', 0) 
                for event in refactoring_events
            ) / total_analyses
            
            total_issues = sum(
                event.get('additional_data', {}).get('issues_count', 0) 
                for event in refactoring_events
            )
            
            report = {
                "summary": f"Analyzed {total_analyses} code segments",
                "total_analyses": total_analyses,
                "average_maintainability_score": round(avg_maintainability, 2),
                "total_issues_found": total_issues,
                "recent_analyses": refactoring_events[-10:],  # Last 10 analyses
                "recommendations": [
                    "Focus on code segments with maintainability score < 6",
                    "Prioritize high-severity issues first",
                    "Implement suggested design patterns gradually"
                ]
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating refactoring report: {e}")
            return {
                "summary": f"Error generating report: {str(e)}",
                "total_analyses": 0,
                "recommendations": ["Check system logs for errors"]
            }

def main():
    """Test the Code Refactoring Agent"""
    agent = CodeRefactoringAgent()
    
    # Test with a sample code snippet
    sample_code = '''
def process_data(data):
    if data is not None:
        if len(data) > 0:
            result = []
            for item in data:
                if item is not None:
                    if item > 0:
                        result.append(item * 2)
            return result
    return None
    '''
    
    print("Testing Code Refactoring Agent...")
    analysis = agent.analyze_code_quality(sample_code, "python", "Data processing function")
    print(f"Analysis completed: {json.dumps(analysis, indent=2)}")
    
    # Test pattern suggestions
    pattern_suggestions = agent.suggest_refactoring_patterns(sample_code, "python")
    print(f"Pattern suggestions: {json.dumps(pattern_suggestions, indent=2)}")
    
    # Generate report
    report = agent.get_refactoring_report()
    print(f"Refactoring report: {json.dumps(report, indent=2)}")

if __name__ == "__main__":
    main()