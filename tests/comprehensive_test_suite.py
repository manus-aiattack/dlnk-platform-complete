"""
Comprehensive Test Suite for dLNk Attack Platform
Tests all major components and integrations
"""

import asyncio
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestRunner:
    """Comprehensive test runner"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []
    
    async def run_test(self, test_name: str, test_func):
        """Run a single test"""
        
        print(f"  Testing: {test_name}...", end=" ")
        
        try:
            start_time = time.time()
            result = await test_func()
            execution_time = time.time() - start_time
            
            if result:
                print(f"✅ PASS ({execution_time:.3f}s)")
                self.tests_passed += 1
                self.test_results.append({
                    'name': test_name,
                    'status': 'PASS',
                    'time': execution_time
                })
            else:
                print(f"❌ FAIL ({execution_time:.3f}s)")
                self.tests_failed += 1
                self.test_results.append({
                    'name': test_name,
                    'status': 'FAIL',
                    'time': execution_time
                })
            
            return result
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            self.tests_failed += 1
            self.test_results.append({
                'name': test_name,
                'status': 'ERROR',
                'error': str(e)
            })
            return False
    
    async def run_all_tests(self):
        """Run all tests"""
        
        print("=" * 80)
        print("dLNk ATTACK PLATFORM - COMPREHENSIVE TEST SUITE")
        print("=" * 80)
        print()
        
        # Phase 1: Core Components
        print("[Phase 1] Testing Core Components...")
        await self.test_core_components()
        print()
        
        # Phase 2: AI System
        print("[Phase 2] Testing AI System...")
        await self.test_ai_system()
        print()
        
        # Phase 3: Zero-Day Hunter
        print("[Phase 3] Testing Zero-Day Hunter...")
        await self.test_zeroday_hunter()
        print()
        
        # Phase 4: Self-Learning
        print("[Phase 4] Testing Self-Learning...")
        await self.test_self_learning()
        print()
        
        # Phase 5: API Endpoints
        print("[Phase 5] Testing API Endpoints...")
        await self.test_api_endpoints()
        print()
        
        # Phase 6: Performance
        print("[Phase 6] Testing Performance...")
        await self.test_performance()
        print()
        
        # Phase 7: Security
        print("[Phase 7] Testing Security...")
        await self.test_security()
        print()
        
        # Print summary
        self.print_summary()
    
    async def test_core_components(self):
        """Test core components"""
        
        # Test One-Click Orchestrator
        async def test_orchestrator():
            from core.one_click_orchestrator import OneClickOrchestrator
            orchestrator = OneClickOrchestrator()
            return orchestrator is not None
        
        await self.run_test("One-Click Orchestrator", test_orchestrator)
        
        # Test Error Detector
        async def test_error_detector():
            from core.self_healing.error_detector import ErrorDetector
            detector = ErrorDetector()
            stats = await detector.get_error_statistics()
            return 'total_errors' in stats
        
        await self.run_test("Error Detector", test_error_detector)
    
    async def test_ai_system(self):
        """Test AI system"""
        
        # Test Custom AI Engine
        async def test_ai_engine():
            from core.ai_system.custom_ai_engine import CustomAIEngine
            engine = CustomAIEngine()
            result = await engine.detect_vulnerabilities("test code")
            return 'vulnerabilities' in result
        
        await self.run_test("Custom AI Engine", test_ai_engine)
        
        # Test ML Vulnerability Detector
        async def test_ml_detector():
            from core.ai_models.ml_vulnerability_detector import MLVulnerabilityDetector
            detector = MLVulnerabilityDetector()
            result = await detector.detect("http://test.com")
            return 'vulnerabilities' in result
        
        await self.run_test("ML Vulnerability Detector", test_ml_detector)
        
        # Test AI Decision Engine
        async def test_decision_engine():
            from core.ai_models.ai_decision_engine import AIDecisionEngine
            engine = AIDecisionEngine()
            decision = await engine.decide_attack_strategy({})
            return 'strategy' in decision
        
        await self.run_test("AI Decision Engine", test_decision_engine)
    
    async def test_zeroday_hunter(self):
        """Test Zero-Day Hunter"""
        
        # Test Grammar Fuzzer
        async def test_grammar_fuzzer():
            from advanced_agents.fuzzing.grammar_fuzzer import GrammarFuzzer
            fuzzer = GrammarFuzzer()
            inputs = await fuzzer.generate_inputs('http_request', count=5)
            return len(inputs) == 5
        
        await self.run_test("Grammar Fuzzer", test_grammar_fuzzer)
        
        # Test Corpus Manager
        async def test_corpus_manager():
            from advanced_agents.fuzzing.corpus_manager import CorpusManager
            manager = CorpusManager()
            item_id = await manager.add_corpus_item(b'test data', {1, 2, 3})
            return item_id is not None
        
        await self.run_test("Corpus Manager", test_corpus_manager)
        
        # Test Taint Analyzer
        async def test_taint_analyzer():
            from advanced_agents.taint.dynamic_taint import DynamicTaintAnalyzer
            analyzer = DynamicTaintAnalyzer()
            result = await analyzer.analyze_code("test = input()", 'python')
            return 'taint_flows' in result
        
        await self.run_test("Taint Analyzer", test_taint_analyzer)
        
        # Test ROP Generator
        async def test_rop_generator():
            from advanced_agents.exploit_gen.rop_generator import ROPGenerator
            generator = ROPGenerator()
            gadgets = await generator.find_gadgets('/bin/ls')
            return len(gadgets) > 0
        
        await self.run_test("ROP Generator", test_rop_generator)
        
        # Test Shellcode Generator
        async def test_shellcode_generator():
            from advanced_agents.exploit_gen.shellcode_generator import ShellcodeGenerator
            generator = ShellcodeGenerator()
            shellcode = await generator.generate_execve_shellcode()
            return len(shellcode) > 0
        
        await self.run_test("Shellcode Generator", test_shellcode_generator)
        
        # Test Exploit Tester
        async def test_exploit_tester():
            from advanced_agents.exploit_validation.exploit_tester import ExploitTester
            tester = ExploitTester()
            result = await tester.test_exploit("test", "http://test.com", iterations=2)
            return 'success_rate' in result
        
        await self.run_test("Exploit Tester", test_exploit_tester)
    
    async def test_self_learning(self):
        """Test self-learning system"""
        
        # Test Adaptive Learner
        async def test_adaptive_learner():
            from core.self_learning.adaptive_learner import AdaptiveLearner
            learner = AdaptiveLearner()
            
            attack_data = {
                'type': 'test',
                'target': 'http://test.com',
                'strategy': 'test_strategy',
                'parameters': {}
            }
            
            result = {'success': True, 'execution_time': 1.0, 'vulnerabilities': []}
            
            await learner.learn_from_attack(attack_data, result)
            
            stats = await learner.get_learning_statistics()
            return stats['total_attacks'] > 0
        
        await self.run_test("Adaptive Learner", test_adaptive_learner)
    
    async def test_api_endpoints(self):
        """Test API endpoints"""
        
        # Test if API routes are importable
        async def test_zeroday_routes():
            from api.routes.zeroday_routes import router
            return router is not None
        
        await self.run_test("Zero-Day API Routes", test_zeroday_routes)
        
        async def test_learning_routes():
            from api.routes.learning_routes import router
            return router is not None
        
        await self.run_test("Learning API Routes", test_learning_routes)
    
    async def test_performance(self):
        """Test performance components"""
        
        # Test Performance Monitor
        async def test_performance_monitor():
            from core.performance.performance_monitor import PerformanceMonitor
            monitor = PerformanceMonitor()
            
            async def test_op():
                await asyncio.sleep(0.01)
                return "success"
            
            result = await monitor.track_operation(test_op)
            return result['success'] and 'performance' in result
        
        await self.run_test("Performance Monitor", test_performance_monitor)
        
        # Test Cache Manager
        async def test_cache_manager():
            from core.performance.cache_manager import CacheManager
            cache = CacheManager()
            
            await cache.set('test_key', 'test_value')
            value = await cache.get('test_key')
            
            return value == 'test_value'
        
        await self.run_test("Cache Manager", test_cache_manager)
    
    async def test_security(self):
        """Test security components"""
        
        # Test Security Auditor
        async def test_security_auditor():
            from core.security.security_auditor import SecurityAuditor
            auditor = SecurityAuditor()
            results = await auditor.audit_system()
            return 'score' in results
        
        await self.run_test("Security Auditor", test_security_auditor)
    
    def print_summary(self):
        """Print test summary"""
        
        print()
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        total_tests = self.tests_passed + self.tests_failed
        pass_rate = (self.tests_passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {self.tests_passed} ✅")
        print(f"Failed: {self.tests_failed} ❌")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print()
        
        if pass_rate >= 80:
            print("🎉 EXCELLENT! System is production-ready.")
        elif pass_rate >= 60:
            print("✅ GOOD! Minor issues need attention.")
        else:
            print("⚠️  WARNING! Significant issues detected.")
        
        print("=" * 80)
        
        return pass_rate


async def main():
    """Main test function"""
    
    runner = TestRunner()
    await runner.run_all_tests()
    
    # Return exit code based on pass rate
    pass_rate = (runner.tests_passed / (runner.tests_passed + runner.tests_failed) * 100) if (runner.tests_passed + runner.tests_failed) > 0 else 0
    
    if pass_rate >= 80:
        return 0  # Success
    else:
        return 1  # Failure


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

