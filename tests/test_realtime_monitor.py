#!/usr/bin/env python3
"""
Test script for real-time monitoring functionality
"""

import sys
import time
import subprocess
import threading
from pathlib import Path


def test_import():
    """Test that all modules can be imported"""
    print("="*70)
    print("TEST 1: Module Imports")
    print("="*70)
    
    try:
        from src.log_monitor import LogMonitor
        print("✓ LogMonitor imported successfully")
        
        from src.log_parser import ApacheLogParser, LogEntry
        print("✓ ApacheLogParser imported successfully")
        
        from src.threat_detector import ThreatDetector
        print("✓ ThreatDetector imported successfully")
        
        print("\n✅ All imports successful!\n")
        return True
    except Exception as e:
        print(f"\n❌ Import failed: {e}\n")
        return False


def test_log_parsing():
    """Test log parsing functionality"""
    print("="*70)
    print("TEST 2: Log Parsing")
    print("="*70)
    
    from src.log_monitor import LogMonitor
    
    try:
        monitor = LogMonitor("test.log")
        
        # Test parsing valid log line
        test_line = '192.168.1.100 - - [25/Jan/2026:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = monitor._parse_line(test_line)
        
        assert entry is not None, "Failed to parse valid log line"
        assert entry.ip == "192.168.1.100", f"Wrong IP: {entry.ip}"
        assert entry.method == "GET", f"Wrong method: {entry.method}"
        assert entry.status == 200, f"Wrong status: {entry.status}"
        
        print(f"✓ Parsed log entry correctly")
        print(f"  IP: {entry.ip}")
        print(f"  Method: {entry.method}")
        print(f"  Path: {entry.path}")
        print(f"  Status: {entry.status}")
        
        print("\n✅ Log parsing test passed!\n")
        return True
    except Exception as e:
        print(f"\n❌ Log parsing test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def test_threat_detection():
    """Test threat detection patterns"""
    print("="*70)
    print("TEST 3: Threat Detection")
    print("="*70)
    
    from src.log_monitor import LogMonitor
    
    try:
        monitor = LogMonitor("test.log", threat_detector_config={'enabled': True})
        
        # Test SQL injection detection
        sqli_line = '198.51.100.23 - - [25/Jan/2026:10:23:45 +0000] "GET /page.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 2341 "-" "Mozilla/5.0"'
        entry = monitor._parse_line(sqli_line)
        threats = monitor._check_threats(entry)
        
        assert len(threats) > 0, "Failed to detect SQL injection"
        assert threats[0]['type'] == 'SQL_INJECTION', f"Wrong threat type: {threats[0]['type']}"
        print(f"✓ Detected SQL injection")
        
        # Test XSS detection
        xss_line = '198.51.100.23 - - [25/Jan/2026:10:23:45 +0000] "GET /search.php?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 2341 "-" "Mozilla/5.0"'
        entry = monitor._parse_line(xss_line)
        threats = monitor._check_threats(entry)
        
        assert len(threats) > 0, "Failed to detect XSS"
        assert threats[0]['type'] == 'XSS', f"Wrong threat type: {threats[0]['type']}"
        print(f"✓ Detected XSS")
        
        # Test path traversal detection
        path_line = '203.0.113.45 - - [25/Jan/2026:10:23:45 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 404 512 "-" "python-requests/2.28.0"'
        entry = monitor._parse_line(path_line)
        threats = monitor._check_threats(entry)
        
        assert len(threats) > 0, "Failed to detect path traversal"
        print(f"✓ Detected path traversal")
        
        # Test suspicious user agent
        scanner_line = '198.51.100.30 - - [25/Jan/2026:10:23:45 +0000] "GET /admin/ HTTP/1.1" 404 512 "-" "Nikto/2.1.6"'
        entry = monitor._parse_line(scanner_line)
        threats = monitor._check_threats(entry)
        
        assert len(threats) > 0, "Failed to detect suspicious user agent"
        print(f"✓ Detected suspicious user agent")
        
        print("\n✅ All threat detection tests passed!\n")
        return True
    except Exception as e:
        print(f"\n❌ Threat detection test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def test_simulator():
    """Test log simulator"""
    print("="*70)
    print("TEST 4: Log Simulator")
    print("="*70)
    
    test_file = "data/sample_logs/test_sim.log"
    
    try:
        # Clean up test file
        test_path = Path(test_file)
        if test_path.exists():
            test_path.unlink()
        
        print(f"Testing simulator with 5 entries...")
        
        # Run simulator for 5 entries
        import simulate_logs
        
        # Use threading to run simulator
        def run_sim():
            simulate_logs.simulate_logs(test_file, interval=0.2, count=5)
        
        thread = threading.Thread(target=run_sim)
        thread.start()
        thread.join(timeout=5)
        
        # Check if file was created and has entries
        if test_path.exists():
            with open(test_file, 'r') as f:
                lines = f.readlines()
            
            print(f"✓ Generated {len(lines)} log entries")
            assert len(lines) == 5, f"Expected 5 entries, got {len(lines)}"
            
            # Clean up
            test_path.unlink()
            
            print("\n✅ Simulator test passed!\n")
            return True
        else:
            print(f"\n❌ Simulator failed to create log file\n")
            return False
            
    except Exception as e:
        print(f"\n❌ Simulator test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def test_end_to_end():
    """Test complete workflow"""
    print("="*70)
    print("TEST 5: End-to-End Integration Test")
    print("="*70)
    
    test_file = "data/sample_logs/test_e2e.log"
    
    try:
        # Clean up test file
        test_path = Path(test_file)
        if test_path.exists():
            test_path.unlink()
        
        print("Testing complete monitoring workflow...")
        print("This test will run for 3 seconds...\n")
        
        # Import modules
        from src.log_monitor import LogMonitor
        import simulate_logs
        
        # Start monitor in thread
        monitor = LogMonitor(test_file, threat_detector_config={'enabled': True})
        
        def run_monitor():
            try:
                monitor.start()
            except:
                pass
        
        monitor_thread = threading.Thread(target=run_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Give monitor time to start
        time.sleep(0.5)
        
        # Generate some logs
        simulate_logs.simulate_logs(test_file, interval=0.3, count=5)
        
        # Wait a bit more
        time.sleep(0.5)
        
        # Stop monitor
        monitor.stop()
        time.sleep(0.5)
        
        print(f"\n✓ Processed {monitor.total_entries} entries")
        print(f"✓ Detected {monitor.total_threats} threats")
        
        # Clean up
        if test_path.exists():
            test_path.unlink()
        
        print("\n✅ End-to-end test passed!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ End-to-end test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("REAL-TIME MONITORING TEST SUITE")
    print("="*70 + "\n")
    
    results = []
    
    # Run tests
    results.append(("Import Test", test_import()))
    results.append(("Log Parsing Test", test_log_parsing()))
    results.append(("Threat Detection Test", test_threat_detection()))
    results.append(("Simulator Test", test_simulator()))
    results.append(("End-to-End Test", test_end_to_end()))
    
    # Print summary
    print("="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    total = len(results)
    passed = sum(1 for _, r in results if r)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Real-time monitoring is ready to use.")
        print("\nNext steps:")
        print("1. Try: python simulate_logs.py -i 1")
        print("2. In another terminal: python main.py --monitor data/sample_logs/live.log --detect-threats")
    else:
        print("\n⚠️  Some tests failed. Please check the errors above.")
        sys.exit(1)


if __name__ == '__main__':
    main()