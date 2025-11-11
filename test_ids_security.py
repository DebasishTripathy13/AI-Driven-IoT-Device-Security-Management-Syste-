"""
IDS Security Testing Script
Tests various attack patterns to validate IDS functionality
"""
import requests
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import random

class IDSSecurityTester:
    def __init__(self, api_base_url="http://localhost:8001"):
        self.api_url = api_base_url
        self.session = requests.Session()
        
    def test_sql_injection(self):
        """Test SQL injection detection"""
        print("🔍 Testing SQL Injection Detection...")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM admin --",
            "admin' OR 1=1 /*",
            "1' AND (SELECT COUNT(*) FROM admin) > 0 --"
        ]
        
        results = []
        for payload in sql_payloads:
            try:
                response = self.session.post(
                    f"{self.api_url}/api/devices/connect",
                    json={"deviceIds": [payload]},
                    timeout=5
                )
                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 Payload: {payload[:30]}... -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with payload {payload}: {e}")
                
        return results
    
    def test_code_injection(self):
        """Test code injection detection"""
        print("🔍 Testing Code Injection Detection...")
        
        code_payloads = [
            "import os; os.system('rm -rf /')",
            "eval('__import__(\"os\").system(\"ls\")')",
            "exec('print(\"hacked\")')",
            "import subprocess; subprocess.call(['cat', '/etc/passwd'])",
            "__import__('os').system('whoami')"
        ]
        
        results = []
        for payload in code_payloads:
            try:
                response = self.session.post(
                    f"{self.api_url}/api/devices/med-test-001/code",
                    json={"code": payload, "language": "python"},
                    timeout=5
                )
                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 Payload: {payload[:30]}... -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with payload {payload}: {e}")
                
        return results
    
    def test_command_injection(self):
        """Test command injection detection"""
        print("🔍 Testing Command Injection Detection...")
        
        command_payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "&& rm -rf /",
            "; nc -l 4444",
            "$(cat /etc/shadow)"
        ]
        
        results = []
        for payload in command_payloads:
            try:
                response = self.session.post(
                    f"{self.api_url}/api/messages/send",
                    json={
                        "deviceIds": ["med-test-001"],
                        "messageType": "command",
                        "content": {"command": payload}
                    },
                    timeout=5
                )
                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 Payload: {payload} -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with payload {payload}: {e}")
                
        return results
    
    def test_xss_attacks(self):
        """Test XSS detection"""
        print("🔍 Testing XSS Detection...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        results = []
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    f"{self.api_url}/api/messages/send",
                    json={
                        "deviceIds": ["med-test-001"],
                        "messageType": "alert",
                        "content": {"message": payload}
                    },
                    timeout=5
                )
                results.append({
                    "payload": payload,  
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 Payload: {payload[:30]}... -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with payload {payload}: {e}")
                
        return results
    
    def test_suspicious_user_agents(self):
        """Test suspicious user agent detection"""
        print("🔍 Testing Suspicious User Agent Detection...")
        
        suspicious_agents = [
            "sqlmap/1.4.9",
            "Nmap Scripting Engine",
            "Nikto/2.1.6",
            "python-requests/2.25.1",
            "curl/7.68.0"
        ]
        
        results = []
        for agent in suspicious_agents:
            try:
                response = self.session.get(
                    f"{self.api_url}/api/devices",
                    headers={"User-Agent": agent},
                    timeout=5
                )
                results.append({
                    "user_agent": agent,
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 User-Agent: {agent} -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with agent {agent}: {e}")
                
        return results
    
    def test_flood_attack(self, duration_seconds=5, requests_per_second=250):
        """Test flood detection (scaled down for testing)"""
        print(f"🔍 Testing Flood Detection ({requests_per_second} req/s for {duration_seconds}s)...")
        
        def make_request():
            try:
                response = self.session.get(f"{self.api_url}/api/devices", timeout=1)
                return response.status_code
            except:
                return 0
        
        start_time = time.time()
        total_requests = 0
        blocked_requests = 0
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            while time.time() - start_time < duration_seconds:
                futures = []
                for _ in range(requests_per_second):
                    futures.append(executor.submit(make_request))
                
                for future in futures:
                    try:
                        status_code = future.result(timeout=2)
                        total_requests += 1
                        if status_code == 403:
                            blocked_requests += 1
                    except:
                        pass
                
                time.sleep(1)
        
        print(f"  📊 Total Requests: {total_requests}")
        print(f"  🚫 Blocked Requests: {blocked_requests}")
        print(f"  📈 Block Rate: {(blocked_requests/total_requests)*100:.1f}%")
        
        return {
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "block_rate": (blocked_requests/total_requests)*100 if total_requests > 0 else 0
        }
    
    def test_unauthorized_endpoints(self):
        """Test unauthorized access detection"""
        print("🔍 Testing Unauthorized Access Detection...")
        
        unauthorized_tests = [
            ("GET", "/admin/secret"),
            ("GET", "/.env"),
            ("GET", "/config"),
            ("PATCH", "/api/devices/med-test-001"),
            ("DELETE", "/api/devices/med-test-001")
        ]
        
        results = []
        for method, path in unauthorized_tests:
            try:
                response = self.session.request(
                    method,
                    f"{self.api_url}{path}",
                    json={"data": "test"} if method in ["PATCH", "DELETE"] else None,
                    timeout=5
                )
                results.append({
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  📤 {method} {path} -> Status: {response.status_code}")
                
            except requests.RequestException as e:
                print(f"  ❌ Error with {method} {path}: {e}")
                
        return results
    
    def run_comprehensive_test(self):
        """Run all security tests"""
        print("🛡️ Starting Comprehensive IDS Security Testing")
        print("=" * 60)
        
        all_results = {}
        
        # Test various attack types
        all_results["sqli"] = self.test_sql_injection()
        print()
        
        all_results["code_injection"] = self.test_code_injection()
        print()
        
        all_results["command_injection"] = self.test_command_injection()
        print()
        
        all_results["xss"] = self.test_xss_attacks()
        print()
        
        all_results["suspicious_agents"] = self.test_suspicious_user_agents()
        print()
        
        all_results["unauthorized"] = self.test_unauthorized_endpoints()
        print()
        
        all_results["flood"] = self.test_flood_attack()
        print()
        
        # Summary
        print("📊 Test Summary:")
        print("=" * 40)
        
        for test_type, results in all_results.items():
            if test_type == "flood":
                print(f"{test_type.upper()}: {results['blocked_requests']}/{results['total_requests']} blocked")
            else:
                blocked = sum(1 for r in results if r.get('blocked', False))
                total = len(results)
                print(f"{test_type.upper()}: {blocked}/{total} blocked")
        
        return all_results
    
    def check_admin_dashboard(self):
        """Test admin dashboard accessibility"""
        print("🔍 Testing Admin Dashboard...")
        
        try:
            response = self.session.get(f"{self.api_url}/admin/", timeout=10)
            if response.status_code == 200:
                print("  ✅ Admin Dashboard accessible")
                print(f"  📄 Response length: {len(response.text)} bytes")
            else:
                print(f"  ❌ Admin Dashboard error: {response.status_code}")
                
        except requests.RequestException as e:
            print(f"  ❌ Admin Dashboard error: {e}")


def main():
    """Main testing function"""
    tester = IDSSecurityTester()
    
    # Check if API server is running
    try:
        response = tester.session.get(f"{tester.api_url}/health", timeout=5)
        if response.status_code != 200:
            print("❌ API Server not responding. Please start the API server first.")
            return
    except requests.RequestException:
        print("❌ Cannot connect to API server. Please ensure it's running on port 8001.")
        return
    
    print("✅ API Server is running. Starting security tests...\n")
    
    # Test admin dashboard
    tester.check_admin_dashboard()
    print()
    
    # Run comprehensive security tests
    results = tester.run_comprehensive_test()
    
    print("\n🎯 Testing Complete!")
    print("Check the IDS logs and admin dashboard for detailed security events.")
    print(f"Admin Dashboard: {tester.api_url}/admin/")


if __name__ == "__main__":
    main()