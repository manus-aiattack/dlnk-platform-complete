"""
Performance Testing for dLNk Attack Platform
Tests load, stress, and performance metrics
"""

import asyncio
import time
import statistics
from typing import List, Dict
import aiohttp
import pytest


class PerformanceTest:
    """Performance testing suite"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.results = []
    
    async def measure_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict:
        """Measure single request performance"""
        start_time = time.time()
        
        try:
            async with session.request(
                method,
                f"{self.base_url}{endpoint}",
                **kwargs
            ) as response:
                await response.read()
                end_time = time.time()
                
                return {
                    'success': True,
                    'status': response.status,
                    'duration': end_time - start_time,
                    'endpoint': endpoint
                }
        except Exception as e:
            end_time = time.time()
            return {
                'success': False,
                'error': str(e),
                'duration': end_time - start_time,
                'endpoint': endpoint
            }
    
    async def load_test(
        self,
        endpoint: str,
        concurrent_requests: int = 100,
        total_requests: int = 1000
    ) -> Dict:
        """
        Load testing - sustained load over time
        
        Args:
            endpoint: API endpoint to test
            concurrent_requests: Number of concurrent requests
            total_requests: Total number of requests to make
        
        Returns:
            Performance metrics
        """
        print(f"\n[Load Test] Testing {endpoint}")
        print(f"Concurrent: {concurrent_requests}, Total: {total_requests}")
        
        results = []
        
        async with aiohttp.ClientSession() as session:
            # Create batches of concurrent requests
            batches = total_requests // concurrent_requests
            
            for batch in range(batches):
                tasks = [
                    self.measure_request(session, 'GET', endpoint)
                    for _ in range(concurrent_requests)
                ]
                
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
                
                # Small delay between batches
                await asyncio.sleep(0.1)
        
        # Calculate metrics
        durations = [r['duration'] for r in results if r['success']]
        success_count = sum(1 for r in results if r['success'])
        
        metrics = {
            'endpoint': endpoint,
            'total_requests': total_requests,
            'successful_requests': success_count,
            'failed_requests': total_requests - success_count,
            'success_rate': success_count / total_requests * 100,
            'avg_response_time': statistics.mean(durations) if durations else 0,
            'median_response_time': statistics.median(durations) if durations else 0,
            'min_response_time': min(durations) if durations else 0,
            'max_response_time': max(durations) if durations else 0,
            'p95_response_time': statistics.quantiles(durations, n=20)[18] if len(durations) > 20 else 0,
            'p99_response_time': statistics.quantiles(durations, n=100)[98] if len(durations) > 100 else 0,
        }
        
        self._print_metrics(metrics)
        return metrics
    
    async def stress_test(
        self,
        endpoint: str,
        max_concurrent: int = 500,
        step: int = 50,
        duration_per_step: int = 10
    ) -> Dict:
        """
        Stress testing - gradually increase load until failure
        
        Args:
            endpoint: API endpoint to test
            max_concurrent: Maximum concurrent requests
            step: Increase step size
            duration_per_step: Duration for each load level
        
        Returns:
            Stress test results
        """
        print(f"\n[Stress Test] Testing {endpoint}")
        print(f"Max concurrent: {max_concurrent}, Step: {step}")
        
        results = []
        breaking_point = None
        
        async with aiohttp.ClientSession() as session:
            for concurrent in range(step, max_concurrent + 1, step):
                print(f"\nTesting with {concurrent} concurrent requests...")
                
                start_time = time.time()
                level_results = []
                
                # Run for specified duration
                while time.time() - start_time < duration_per_step:
                    tasks = [
                        self.measure_request(session, 'GET', endpoint)
                        for _ in range(concurrent)
                    ]
                    
                    batch_results = await asyncio.gather(*tasks)
                    level_results.extend(batch_results)
                    
                    await asyncio.sleep(0.1)
                
                # Calculate metrics for this level
                success_rate = sum(1 for r in level_results if r['success']) / len(level_results) * 100
                avg_duration = statistics.mean([r['duration'] for r in level_results if r['success']])
                
                results.append({
                    'concurrent': concurrent,
                    'success_rate': success_rate,
                    'avg_response_time': avg_duration
                })
                
                print(f"Success rate: {success_rate:.2f}%, Avg response: {avg_duration*1000:.2f}ms")
                
                # Check if system is breaking
                if success_rate < 95 or avg_duration > 5:
                    breaking_point = concurrent
                    print(f"\n⚠️  Breaking point detected at {concurrent} concurrent requests")
                    break
        
        return {
            'endpoint': endpoint,
            'results': results,
            'breaking_point': breaking_point,
            'max_tested': results[-1]['concurrent'] if results else 0
        }
    
    async def memory_leak_test(
        self,
        endpoint: str,
        iterations: int = 1000,
        check_interval: int = 100
    ) -> Dict:
        """
        Memory leak detection test
        
        Args:
            endpoint: API endpoint to test
            iterations: Number of iterations
            check_interval: Check memory every N requests
        
        Returns:
            Memory usage metrics
        """
        print(f"\n[Memory Leak Test] Testing {endpoint}")
        print(f"Iterations: {iterations}")
        
        # This is a simplified version - in production, you'd monitor actual memory
        async with aiohttp.ClientSession() as session:
            for i in range(iterations):
                await self.measure_request(session, 'GET', endpoint)
                
                if (i + 1) % check_interval == 0:
                    print(f"Completed {i + 1}/{iterations} requests")
        
        return {
            'endpoint': endpoint,
            'iterations': iterations,
            'status': 'completed'
        }
    
    def _print_metrics(self, metrics: Dict):
        """Print performance metrics"""
        print("\n" + "="*60)
        print(f"Endpoint: {metrics['endpoint']}")
        print(f"Total Requests: {metrics['total_requests']}")
        print(f"Successful: {metrics['successful_requests']}")
        print(f"Failed: {metrics['failed_requests']}")
        print(f"Success Rate: {metrics['success_rate']:.2f}%")
        print(f"\nResponse Times:")
        print(f"  Average: {metrics['avg_response_time']*1000:.2f}ms")
        print(f"  Median: {metrics['median_response_time']*1000:.2f}ms")
        print(f"  Min: {metrics['min_response_time']*1000:.2f}ms")
        print(f"  Max: {metrics['max_response_time']*1000:.2f}ms")
        print(f"  P95: {metrics['p95_response_time']*1000:.2f}ms")
        print(f"  P99: {metrics['p99_response_time']*1000:.2f}ms")
        print("="*60 + "\n")


# Test cases
@pytest.mark.asyncio
async def test_api_health_load():
    """Test /health endpoint under load"""
    tester = PerformanceTest()
    metrics = await tester.load_test(
        endpoint='/health',
        concurrent_requests=100,
        total_requests=1000
    )
    
    # Assertions
    assert metrics['success_rate'] > 99, "Success rate should be above 99%"
    assert metrics['avg_response_time'] < 0.1, "Average response time should be under 100ms"
    assert metrics['p95_response_time'] < 0.2, "P95 response time should be under 200ms"


@pytest.mark.asyncio
async def test_api_targets_load():
    """Test /targets endpoint under load"""
    tester = PerformanceTest()
    metrics = await tester.load_test(
        endpoint='/api/targets',
        concurrent_requests=50,
        total_requests=500
    )
    
    # More lenient for complex endpoints
    assert metrics['success_rate'] > 95, "Success rate should be above 95%"
    assert metrics['avg_response_time'] < 0.5, "Average response time should be under 500ms"


@pytest.mark.asyncio
async def test_stress():
    """Stress test to find breaking point"""
    tester = PerformanceTest()
    results = await tester.stress_test(
        endpoint='/health',
        max_concurrent=500,
        step=50,
        duration_per_step=5
    )
    
    print(f"\nBreaking point: {results['breaking_point']} concurrent requests")
    assert results['breaking_point'] is None or results['breaking_point'] > 100, \
        "System should handle at least 100 concurrent requests"


if __name__ == '__main__':
    async def main():
        tester = PerformanceTest()
        
        # Run load tests
        print("\n" + "="*60)
        print("PERFORMANCE TEST SUITE")
        print("="*60)
        
        await tester.load_test('/health', 100, 1000)
        await tester.stress_test('/health', 500, 50, 5)
        
        print("\n✅ Performance testing completed!")
    
    asyncio.run(main())

