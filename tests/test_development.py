#!/usr/bin/env python3.11
"""
dLNk Attack Platform - Development Testing Suite
Comprehensive testing for all components
"""

import asyncio
import sys
import os
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test results
test_results = {
    'passed': 0,
    'failed': 0,
    'skipped': 0,
    'errors': []
}


def test_header(name: str):
    """Print test header"""
    print(f"\n{'='*80}")
    print(f"  {name}")
    print(f"{'='*80}")


def test_result(name: str, passed: bool, message: str = ""):
    """Record and print test result"""
    if passed:
        test_results['passed'] += 1
        status = "✅ PASS"
    else:
        test_results['failed'] += 1
        status = "❌ FAIL"
        test_results['errors'].append(f"{name}: {message}")
    
    print(f"{status} - {name}")
    if message and not passed:
        print(f"       Error: {message}")


# ============================================================================
# UNIT TESTS
# ============================================================================

def test_custom_ai_engine():
    """Test Custom AI Engine"""
    test_header("Unit Test: Custom AI Engine")
    
    try:
        from core.ai_system.custom_ai_engine import CustomAIEngine
        
        async def run_test():
            engine = CustomAIEngine()
            
            # Test 1: Vulnerability analysis
            response_data = "mysql_fetch_array() error in your SQL syntax"
            vulns = await engine.analyze_vulnerabilities(
                target_url='http://test.com',
                response_data=response_data
            )
            
            test_result(
                "AI Engine - Vulnerability Detection",
                len(vulns) > 0,
                f"Expected vulnerabilities, got {len(vulns)}"
            )
            
            # Test 2: Exploit generation
            exploits = await engine.generate_exploits(vulns)
            test_result(
                "AI Engine - Exploit Generation",
                len(exploits) > 0,
                f"Expected exploits, got {len(exploits)}"
            )
            
            # Test 3: Attack path optimization
            optimized = await engine.optimize_attack_path(vulns)
            test_result(
                "AI Engine - Attack Path Optimization",
                len(optimized) == len(vulns),
                f"Expected {len(vulns)} vulns, got {len(optimized)}"
            )
            
            # Test 4: Success rate prediction
            if exploits:
                success_rate = await engine.predict_success_rate(
                    exploits[0],
                    {'technologies': ['PHP 5.6']}
                )
                test_result(
                    "AI Engine - Success Rate Prediction",
                    0.0 <= success_rate <= 1.0,
                    f"Expected 0-1, got {success_rate}"
                )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("Custom AI Engine", False, str(e))


def test_vulnerability_analyzer():
    """Test AI Vulnerability Analyzer"""
    test_header("Unit Test: AI Vulnerability Analyzer")
    
    try:
        from core.ai_system.vulnerability_analyzer import AIVulnerabilityAnalyzer
        
        async def run_test():
            analyzer = AIVulnerabilityAnalyzer()
            
            # Test analysis
            result = await analyzer.run({
                'url': 'http://test.com',
                'response_data': 'error in your SQL syntax',
                'scan_results': {
                    'open_ports': [{'port': 80, 'service': 'http'}]
                }
            })
            
            test_result(
                "Vulnerability Analyzer - Analysis",
                result.get('success') == True,
                f"Expected success=True, got {result.get('success')}"
            )
            
            test_result(
                "Vulnerability Analyzer - Vulnerabilities Found",
                len(result.get('vulnerabilities', [])) > 0,
                f"Expected vulnerabilities, got {len(result.get('vulnerabilities', []))}"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("Vulnerability Analyzer", False, str(e))


def test_pattern_learner():
    """Test Pattern Learner"""
    test_header("Unit Test: Pattern Learner")
    
    try:
        from core.self_learning.pattern_learner import PatternLearner
        
        async def run_test():
            learner = PatternLearner()
            
            # Test learning from attack
            attack_result = {
                'target_url': 'http://test.com',
                'attack_type': 'sql_injection',
                'success': True,
                'techniques': ['union_based', 'time_based'],
                'response_time': 1.5
            }
            
            result = await learner.run({
                'attack_result': attack_result,
                'update_knowledge': True
            })
            
            test_result(
                "Pattern Learner - Learning",
                result.get('success') == True,
                f"Expected success=True, got {result.get('success')}"
            )
            
            test_result(
                "Pattern Learner - Patterns Extracted",
                result.get('patterns_learned', 0) > 0,
                f"Expected patterns, got {result.get('patterns_learned', 0)}"
            )
            
            # Test recommendations
            recommendations = await learner.get_recommendations({
                'technology': 'MySQL',
                'attack_type': 'sql_injection'
            })
            
            test_result(
                "Pattern Learner - Recommendations",
                'recommended_techniques' in recommendations,
                "Expected recommendations"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("Pattern Learner", False, str(e))


def test_one_click_orchestrator():
    """Test One-Click Orchestrator"""
    test_header("Unit Test: One-Click Orchestrator")
    
    try:
        from core.one_click_orchestrator import OneClickOrchestrator
        
        async def run_test():
            orchestrator = OneClickOrchestrator()
            
            # Test attack execution
            result = await orchestrator.execute_one_click_attack(
                target_url='http://test.com',
                api_key='test_key'
            )
            
            test_result(
                "Orchestrator - Attack Execution",
                'attack_id' in result,
                "Expected attack_id in result"
            )
            
            test_result(
                "Orchestrator - Phases Completed",
                'phases' in result,
                "Expected phases in result"
            )
            
            test_result(
                "Orchestrator - Success Status",
                result.get('success') == True,
                f"Expected success=True, got {result.get('success')}"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("One-Click Orchestrator", False, str(e))


def test_afl_fuzzer():
    """Test AFL Fuzzer"""
    test_header("Unit Test: AFL Fuzzer")
    
    try:
        from advanced_agents.fuzzing.afl_fuzzer import AFLFuzzer
        
        async def run_test():
            fuzzer = AFLFuzzer()
            
            # Test initialization
            test_result(
                "AFL Fuzzer - Initialization",
                fuzzer is not None,
                "Failed to initialize fuzzer"
            )
            
            # Test run method exists
            test_result(
                "AFL Fuzzer - Run Method",
                hasattr(fuzzer, 'run'),
                "Run method not found"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("AFL Fuzzer", False, str(e))


def test_crash_analyzer():
    """Test Crash Analyzer"""
    test_header("Unit Test: Crash Analyzer")
    
    try:
        from advanced_agents.fuzzing.crash_analyzer import CrashAnalyzer
        
        async def run_test():
            analyzer = CrashAnalyzer()
            
            # Test initialization
            test_result(
                "Crash Analyzer - Initialization",
                analyzer is not None,
                "Failed to initialize analyzer"
            )
            
            # Test run method exists
            test_result(
                "Crash Analyzer - Run Method",
                hasattr(analyzer, 'run'),
                "Run method not found"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("Crash Analyzer", False, str(e))


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_end_to_end_workflow():
    """Test complete end-to-end workflow"""
    test_header("Integration Test: End-to-End Workflow")
    
    try:
        from core.one_click_orchestrator import OneClickOrchestrator
        
        async def run_test():
            orchestrator = OneClickOrchestrator()
            
            # Execute complete attack
            start_time = time.time()
            result = await orchestrator.execute_one_click_attack(
                target_url='http://testphp.vulnweb.com',
                api_key='test_key'
            )
            elapsed = time.time() - start_time
            
            test_result(
                "E2E - Attack Completion",
                result.get('success') == True,
                f"Attack failed: {result.get('error', 'Unknown error')}"
            )
            
            test_result(
                "E2E - Response Time",
                elapsed < 60,  # Should complete within 60 seconds
                f"Too slow: {elapsed:.2f}s"
            )
            
            test_result(
                "E2E - All Phases Executed",
                len(result.get('phases', {})) >= 5,
                f"Expected 5+ phases, got {len(result.get('phases', {}))}"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("End-to-End Workflow", False, str(e))


def test_ai_integration():
    """Test AI system integration"""
    test_header("Integration Test: AI System Integration")
    
    try:
        from core.ai_system.vulnerability_analyzer import AIVulnerabilityAnalyzer
        from core.self_learning.pattern_learner import PatternLearner
        
        async def run_test():
            analyzer = AIVulnerabilityAnalyzer()
            learner = PatternLearner()
            
            # Test AI analysis
            analysis_result = await analyzer.run({
                'url': 'http://test.com',
                'response_data': 'SQL error',
                'scan_results': {}
            })
            
            test_result(
                "AI Integration - Analysis",
                analysis_result.get('success') == True,
                "AI analysis failed"
            )
            
            # Test learning from analysis
            if analysis_result.get('success'):
                learning_result = await learner.run({
                    'attack_result': {
                        'target_url': 'http://test.com',
                        'attack_type': 'sql_injection',
                        'success': True,
                        'techniques': ['union_based']
                    },
                    'update_knowledge': True
                })
                
                test_result(
                    "AI Integration - Learning",
                    learning_result.get('success') == True,
                    "Learning failed"
                )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("AI System Integration", False, str(e))


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

def test_performance_ai_engine():
    """Test AI engine performance"""
    test_header("Performance Test: AI Engine")
    
    try:
        from core.ai_system.custom_ai_engine import CustomAIEngine
        
        async def run_test():
            engine = CustomAIEngine()
            
            # Test response time
            start_time = time.time()
            
            for i in range(10):
                await engine.analyze_vulnerabilities(
                    target_url='http://test.com',
                    response_data='SQL error test'
                )
            
            elapsed = time.time() - start_time
            avg_time = elapsed / 10
            
            test_result(
                "AI Engine - Average Response Time",
                avg_time < 0.5,  # Should be < 500ms
                f"Too slow: {avg_time*1000:.2f}ms"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("AI Engine Performance", False, str(e))


def test_performance_orchestrator():
    """Test orchestrator performance"""
    test_header("Performance Test: Orchestrator")
    
    try:
        from core.one_click_orchestrator import OneClickOrchestrator
        
        async def run_test():
            orchestrator = OneClickOrchestrator()
            
            # Test attack execution time
            start_time = time.time()
            result = await orchestrator.execute_one_click_attack(
                target_url='http://test.com',
                api_key='test_key'
            )
            elapsed = time.time() - start_time
            
            test_result(
                "Orchestrator - Execution Time",
                elapsed < 30,  # Should complete within 30 seconds
                f"Too slow: {elapsed:.2f}s"
            )
        
        asyncio.run(run_test())
        
    except Exception as e:
        test_result("Orchestrator Performance", False, str(e))


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all tests"""
    
    print("\n" + "="*80)
    print("  dLNk Attack Platform - Development Testing Suite")
    print("="*80)
    
    start_time = time.time()
    
    # Unit Tests
    print("\n" + "="*80)
    print("  UNIT TESTS")
    print("="*80)
    
    test_custom_ai_engine()
    test_vulnerability_analyzer()
    test_pattern_learner()
    test_one_click_orchestrator()
    test_afl_fuzzer()
    test_crash_analyzer()
    
    # Integration Tests
    print("\n" + "="*80)
    print("  INTEGRATION TESTS")
    print("="*80)
    
    test_end_to_end_workflow()
    test_ai_integration()
    
    # Performance Tests
    print("\n" + "="*80)
    print("  PERFORMANCE TESTS")
    print("="*80)
    
    test_performance_ai_engine()
    test_performance_orchestrator()
    
    # Summary
    elapsed = time.time() - start_time
    
    print("\n" + "="*80)
    print("  TEST SUMMARY")
    print("="*80)
    print(f"  Total Tests: {test_results['passed'] + test_results['failed']}")
    print(f"  ✅ Passed: {test_results['passed']}")
    print(f"  ❌ Failed: {test_results['failed']}")
    print(f"  ⏱️  Time: {elapsed:.2f}s")
    print("="*80)
    
    if test_results['failed'] > 0:
        print("\n❌ FAILED TESTS:")
        for error in test_results['errors']:
            print(f"  - {error}")
    
    # Calculate pass rate
    total = test_results['passed'] + test_results['failed']
    if total > 0:
        pass_rate = (test_results['passed'] / total) * 100
        print(f"\n📊 Pass Rate: {pass_rate:.1f}%")
        
        if pass_rate >= 80:
            print("\n✅ DEVELOPMENT TESTING: PASSED")
            return 0
        else:
            print("\n❌ DEVELOPMENT TESTING: FAILED")
            return 1
    
    return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())

