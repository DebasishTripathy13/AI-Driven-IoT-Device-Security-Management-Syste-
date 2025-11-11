# Test AI Security Client directly
import sys
import os
sys.path.append(os.getcwd())

try:
    from ai_security_client import ai_security_client
    print("✅ AI Security Client imported successfully")
    
    # Test health check
    health = ai_security_client.health_check()
    print(f"🏥 AI Service Health: {health}")
    
    # Test a simple analysis
    result = ai_security_client.analyze_request(
        method="POST",
        path="/api/test",
        headers={"Content-Type": "application/json"},
        body={"test": "hello"},
        client_ip="127.0.0.1"
    )
    print(f"🤖 Analysis Result: {result}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()