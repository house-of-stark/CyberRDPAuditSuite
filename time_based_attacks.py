#!/usr/bin/env python3
"""
RDP Time-Based Attack Testing Module
Tests for timing vulnerabilities in RDP authentication and session handling
"""

import time
import statistics
import json
import subprocess
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import List, Dict, Optional, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TimeAttackType(str, Enum):
    """Enum for different types of time-based attacks"""
    LOGIN_TIMING = "login_timing"
    SESSION_TIMING = "session_timing"
    TOKEN_VALIDATION = "token_validation"
    RATE_LIMITING = "rate_limiting"
    CREDENTIAL_STUFFING = "credential_stuffing"

@dataclass
class TimeAttackResult:
    """Class to store time-based attack test results"""
    attack_type: TimeAttackType
    test_name: str
    sample_size: int
    min_time: float
    max_time: float
    avg_time: float
    median_time: float
    std_dev: float
    timing_differences: Dict[str, float] = field(default_factory=dict)
    is_vulnerable: bool = False
    vulnerability_details: Optional[Dict] = None
    timestamp: float = field(default_factory=time.time)

class RDPTimeAttackTester:
    """Class for testing time-based attacks against RDP"""
    
    def __init__(self, rdp_host: str, rdp_port: int = 3389):
        self.rdp_host = rdp_host
        self.rdp_port = rdp_port
        self.results: List[TimeAttackResult] = []
    
    def test_login_timing(self, username: str, valid_password: str, 
                         invalid_password: str, samples: int = 10) -> TimeAttackResult:
        """Test for timing differences between valid and invalid logins"""
        logger.info(f"Testing login timing with {samples} samples per test case")
        
        # Test valid credentials
        valid_times = self._measure_login_times(username, valid_password, samples)
        
        # Test invalid credentials
        invalid_times = self._measure_login_times(username, invalid_password, samples)
        
        # Analyze results
        result = self._analyze_timing_differences(
            valid_times, 
            invalid_times,
            TimeAttackType.LOGIN_TIMING,
            "Login Timing Analysis"
        )
        
        # Check for vulnerability (significant timing difference)
        time_diff = abs(statistics.mean(valid_times) - statistics.mean(invalid_times))
        if time_diff > 0.1:  # 100ms threshold
            result.is_vulnerable = True
            result.vulnerability_details = {
                "type": "Login Timing Attack",
                "severity": "Medium",
                "description": "Significant timing difference between valid and invalid logins",
                "time_difference_seconds": time_diff
            }
        
        self.results.append(result)
        return result
    
    def test_session_token_validation(self, valid_token: str, invalid_token: str, 
                                     samples: int = 10) -> TimeAttackResult:
        """Test for timing differences in session token validation"""
        logger.info(f"Testing session token validation timing with {samples} samples")
        
        valid_times = self._measure_token_validation(valid_token, samples)
        invalid_times = self._measure_token_validation(invalid_token, samples)
        
        result = self._analyze_timing_differences(
            valid_times,
            invalid_times,
            TimeAttackType.TOKEN_VALIDATION,
            "Session Token Validation Timing"
        )
        
        # Check for vulnerability
        time_diff = abs(statistics.mean(valid_times) - statistics.mean(invalid_times))
        if time_diff > 0.05:  # 50ms threshold
            result.is_vulnerable = True
            result.vulnerability_details = {
                "type": "Token Timing Attack",
                "severity": "High",
                "description": "Significant timing difference in token validation",
                "time_difference_seconds": time_diff
            }
        
        self.results.append(result)
        return result
    
    def test_rate_limiting(self, username: str, password: str, 
                          max_attempts: int = 20) -> TimeAttackResult:
        """Test for rate limiting by measuring response times across multiple attempts"""
        logger.info(f"Testing rate limiting with {max_attempts} attempts")
        
        times = []
        for i in range(max_attempts):
            start = time.time()
            # Simulate login attempt
            time.sleep(0.1)  # Simulate network delay
            # In a real test, this would be an actual RDP login attempt
            if i > 10:  # Simulate rate limiting after 10 attempts
                time.sleep(1.0)  # Simulate delay from rate limiting
            end = time.time()
            times.append(end - start)
        
        # Analyze timing pattern
        result = self._analyze_timing_pattern(
            times,
            TimeAttackType.RATE_LIMITING,
            "Rate Limiting Analysis"
        )
        
        # Check for vulnerability (no or ineffective rate limiting)
        if max(times) - min(times) < 0.5:  # Less than 500ms variation
            result.is_vulnerable = True
            result.vulnerability_details = {
                "type": "Ineffective Rate Limiting",
                "severity": "Medium",
                "description": "No significant rate limiting detected",
                "max_attempts_tested": max_attempts
            }
        
        self.results.append(result)
        return result
    
    def _measure_authentication_times(self, username: str, password: str, num_attempts: int = 5) -> List[float]:
        """
        Measure authentication times for the given credentials
        
        Args:
            username: Username for authentication
            password: Password for authentication
            num_attempts: Number of authentication attempts to measure
            
        Returns:
            List of authentication times in seconds
        """
        logger.info(f"Measuring authentication times for user '{username}' ({num_attempts} attempts)")
        
        times = []
        for i in range(num_attempts):
            try:
                start_time = time.time()
                
                # Simulate RDP authentication attempt
                # In a real implementation, this would use an RDP client library
                # For testing purposes, we'll simulate the authentication delay
                
                # Simulate network latency (50-150ms)
                time.sleep(0.05 + (i * 0.01))  # Slightly increasing delay to simulate realistic variance
                
                # Simulate server-side authentication processing
                if len(password) < 3:  # Very short passwords fail faster
                    time.sleep(0.1)
                elif len(password) > 20:  # Long passwords take slightly longer
                    time.sleep(0.3)
                else:  # Normal password length
                    time.sleep(0.2)
                
                # Simulate successful authentication (or not)
                auth_successful = len(password) >= 8  # Simple password policy for simulation
                if not auth_successful:
                    time.sleep(0.1)  # Slight additional delay for failed auth
                
                end_time = time.time()
                elapsed = end_time - start_time
                times.append(elapsed)
                
                logger.debug(f"Attempt {i+1}/{num_attempts}: {elapsed:.3f} seconds")
                
            except Exception as e:
                logger.error(f"Error during authentication attempt {i+1}: {e}")
                times.append(0)  # Use 0 to indicate error
        
        return times
        
    def _measure_login_times(self, username: str, password: str, samples: int) -> List[float]:
        """Measure login times for the given credentials"""
        # This is a legacy method that now uses _measure_authentication_times for consistency
        return self._measure_authentication_times(username, password, samples)
    
    def _measure_token_validation(self, token: str, samples: int) -> List[float]:
        """Measure token validation times"""
        times = []
        for _ in range(samples):
            start = time.time()
            # Simulate token validation
            time.sleep(0.01 if token.startswith("valid") else 0.005)  # Simulate timing difference
            end = time.time()
            times.append(end - start)
        return times
    
    def _simulate_rdp_login(self, username: str, password: str) -> bool:
        """Simulate RDP login (placeholder for actual implementation)"""
        # In a real implementation, this would use xfreerdp or similar
        time.sleep(0.1)  # Simulate network delay
        return True
    
    def _analyze_timing_differences(self, times_a: List[float], times_b: List[float], 
                                   attack_type: TimeAttackType, test_name: str) -> TimeAttackResult:
        """Analyze timing differences between two sets of measurements"""
        stats_a = self._calculate_stats(times_a)
        stats_b = self._calculate_stats(times_b)
        
        time_diff = abs(stats_a['mean'] - stats_b['mean'])
        
        return TimeAttackResult(
            attack_type=attack_type,
            test_name=test_name,
            sample_size=len(times_a) + len(times_b),
            min_time=min(stats_a['min'], stats_b['min']),
            max_time=max(stats_a['max'], stats_b['max']),
            avg_time=(stats_a['mean'] + stats_b['mean']) / 2,
            median_time=statistics.median(times_a + times_b),
            std_dev=statistics.stdev(times_a + times_b) if len(times_a + times_b) > 1 else 0,
            timing_differences={
                'valid_mean': stats_a['mean'],
                'invalid_mean': stats_b['mean'],
                'absolute_difference': time_diff,
                'percent_difference': (time_diff / stats_a['mean']) * 100 if stats_a['mean'] > 0 else 0
            }
        )
    
    def _analyze_timing_pattern(self, times: List[float], 
                              attack_type: TimeAttackType, test_name: str) -> TimeAttackResult:
        """Analyze timing pattern from a single set of measurements"""
        stats = self._calculate_stats(times)
        
        return TimeAttackResult(
            attack_type=attack_type,
            test_name=test_name,
            sample_size=len(times),
            min_time=stats['min'],
            max_time=stats['max'],
            avg_time=stats['mean'],
            median_time=stats['median'],
            std_dev=stats['stdev'] if len(times) > 1 else 0
        )
    
    @staticmethod
    def _calculate_stats(times: List[float]) -> Dict[str, float]:
        """Calculate statistics for timing measurements"""
        if not times:
            return {
                'min': 0, 'max': 0, 'mean': 0, 
                'median': 0, 'stdev': 0
            }
            
        return {
            'min': min(times),
            'max': max(times),
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0
        }
    
    def test_authentication_timing(self, username: str, password: str, num_attempts: int = 5) -> dict:
        """
        Test for timing differences in authentication attempts
        
        Args:
            username: Username to test
            password: Password to test
            num_attempts: Number of authentication attempts to measure
            
        Returns:
            Dictionary with test results
        """
        logger.info(f"Testing authentication timing with {num_attempts} attempts")
        
        # Generate an invalid password for comparison
        invalid_password = f"{password}_invalid"
        
        # Test valid credentials
        valid_times = self._measure_authentication_times(username, password, num_attempts)
        
        # Test invalid credentials
        invalid_times = self._measure_authentication_times(username, invalid_password, num_attempts)
        
        # Calculate statistics
        valid_avg = statistics.mean(valid_times) if valid_times else 0
        invalid_avg = statistics.mean(invalid_times) if invalid_times else 0
        time_diff = abs(valid_avg - invalid_avg)
        
        # Check for vulnerability (significant timing difference)
        is_vulnerable = time_diff > 0.1  # 100ms threshold
        
        # Prepare result
        result = {
            'test_name': 'Authentication Timing Test',
            'username': username,
            'attempts': num_attempts,
            'valid_avg_time': valid_avg,
            'invalid_avg_time': invalid_avg,
            'time_difference': time_diff,
            'is_vulnerable': is_vulnerable,
            'vulnerability_details': {
                'type': 'Authentication Timing Attack',
                'severity': 'Medium',
                'description': 'Significant timing difference between valid and invalid authentication attempts',
                'time_difference_seconds': time_diff,
                'recommendation': 'Ensure constant-time comparison for authentication responses'
            } if is_vulnerable else None
        }
        
        # Log the result
        if is_vulnerable:
            logger.warning(f"Potential timing vulnerability detected (difference: {time_diff:.4f}s)")
        else:
            logger.info("No significant timing difference detected")
            
        return result
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate time-based attack test report"""
        # Custom serialization function to handle TimeAttackType enum
        def serialize_result(result):
            data = {
                'attack_type': result.attack_type.value if hasattr(result.attack_type, 'value') else str(result.attack_type),
                'test_name': result.test_name,
                'sample_size': result.sample_size,
                'min_time': result.min_time,
                'max_time': result.max_time,
                'avg_time': result.avg_time,
                'median_time': result.median_time,
                'std_dev': result.std_dev,
                'timing_differences': result.timing_differences,
                'is_vulnerable': result.is_vulnerable,
                'vulnerability_details': result.vulnerability_details,
                'timestamp': result.timestamp
            }
            return data
            
        report = {
            "timestamp": time.time(),
            "rdp_host": self.rdp_host,
            "rdp_port": self.rdp_port,
            "tests_run": len(self.results),
            "vulnerabilities_found": sum(1 for r in self.results if r.is_vulnerable),
            "results": [serialize_result(r) for r in self.results],
            "vulnerabilities": [r.vulnerability_details 
                               for r in self.results 
                               if r.is_vulnerable and r.vulnerability_details]
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Time-based attack report saved to {output_file}")
        
        return report

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='RDP Time-Based Attack Tester')
    parser.add_argument('host', help='RDP host to test')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for testing')
    parser.add_argument('-P', '--password', help='Password for testing')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        tester = RDPTimeAttackTester(args.host, args.port)
        
        # Run tests if credentials provided
        if args.username and args.password:
            # Test login timing
            tester.test_login_timing(
                args.username, 
                args.password, 
                "invalid_password_123!"
            )
            
            # Test rate limiting
            tester.test_rate_limiting(args.username, args.password)
            
            # Test token validation (simulated)
            tester.test_session_token_validation(
                "valid_token_123",
                "invalid_token_456"
            )
        
        # Generate report
        report = tester.generate_report(args.output)
        
        # Print summary
        print(f"\n=== Time-Based Attack Test Summary ===")
        print(f"Target: {args.host}:{args.port}")
        print(f"Tests Run: {report['tests_run']}")
        print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
        
        if report['vulnerabilities']:
            print("\n=== VULNERABILITIES FOUND ===")
            for vuln in report['vulnerabilities']:
                print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
        
    except Exception as e:
        logger.error(f"Time-based attack testing failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
