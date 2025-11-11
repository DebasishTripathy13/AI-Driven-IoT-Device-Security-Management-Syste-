# Simple AI Agents Test
# Test if AI agents can be imported and initialized properly

def test_ai_agents():
    print("🤖 Testing AI Agents Import and Initialization...")
    print("=" * 50)
    
    try:
        print("📦 Importing AI agents...")
        from code_refactoring_agent import CodeRefactoringAgent
        from optimization_agent import OptimizationAgent  
        from malicious_code_detection_agent import MaliciousCodeDetectionAgent
        print("✅ AI agent imports successful!")
        
        print("\n🏗️ Initializing AI agents...")
        refactoring_agent = CodeRefactoringAgent()
        optimization_agent = OptimizationAgent()
        malware_agent = MaliciousCodeDetectionAgent()
        print("✅ AI agent initialization successful!")
        
        print(f"\n🧠 AI Status:")
        print(f"   Code Refactoring Agent - AI Enabled: {getattr(refactoring_agent, 'ai_enabled', 'Unknown')}")
        print(f"   Optimization Agent - AI Enabled: {getattr(optimization_agent, 'ai_enabled', 'Unknown')}")
        print(f"   Malware Detection Agent - AI Enabled: {getattr(malware_agent, 'ai_enabled', 'Unknown')}")
        
        print("\n🧪 Testing malware detection...")
        test_code = "import os; os.system('rm -rf /')"
        result = malware_agent.scan_code_content(test_code, "python", "test")
        print(f"   Malware scan result: {result}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Initialization Error: {e}")
        return False

if __name__ == "__main__":
    test_ai_agents()