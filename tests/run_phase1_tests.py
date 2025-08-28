#!/usr/bin/env python3
"""
Test Runner for Phase 1 Core Infrastructure

This script runs all Phase 1 tests and provides a summary report.
"""

import sys
import subprocess
from pathlib import Path


def run_tests():
    """Run all Phase 1 tests with detailed output"""
    print("=" * 70)
    print("MeTTa LLM Security Guard - Phase 1 Test Suite")
    print("=" * 70)
    
    test_files = [
        "tests/test_config.py",
        "tests/test_core_types.py", 
        "tests/test_logging_utils.py",
        "tests/test_security_guard.py",
        "tests/test_integration.py"
    ]
    
    results = {}
    overall_success = True
    
    for test_file in test_files:
        print(f"\nRunning {test_file}...")
        print("-" * 50)
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest", 
                test_file, 
                "-v", 
                "--tb=short"
            ], capture_output=True, text=True, timeout=60)
            
            results[test_file] = {
                "success": result.returncode == 0,
                "output": result.stdout,
                "errors": result.stderr
            }
            
            if result.returncode == 0:
                print("✅ PASSED")
            else:
                print("❌ FAILED")
                overall_success = False
                
            # Show output
            if result.stdout:
                print("\nOutput:")
                print(result.stdout)
            
            if result.stderr:
                print("\nErrors:")
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print("❌ TIMEOUT")
            results[test_file] = {"success": False, "output": "", "errors": "Test timed out"}
            overall_success = False
        
        except Exception as e:
            print(f"❌ ERROR: {e}")
            results[test_file] = {"success": False, "output": "", "errors": str(e)}
            overall_success = False
    
    # Summary report
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results.values() if r["success"])
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    for test_file, result in results.items():
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        print(f"{status} {test_file}")
    
    if overall_success:
        print("\n🎉 All Phase 1 tests passed! Core infrastructure is ready.")
        print("\nNext steps:")
        print("- Phase 1 implementation is complete")
        print("- Ready to proceed to Phase 2 (Enhanced Detection)")
        return True
    else:
        print("\n❌ Some tests failed. Please fix issues before proceeding.")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
