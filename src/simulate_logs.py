#!/usr/bin/env python3
"""
Log Simulator - Generates fake log entries for testing real-time monitoring
"""

import time
import random
from datetime import datetime
from pathlib import Path


# Sample log entries (mix of normal and malicious)
SAMPLE_LOGS = [
    # Normal requests
    '192.168.1.100 - - [{timestamp}] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '192.168.1.101 - - [{timestamp}] "GET /about.html HTTP/1.1" 200 2456 "http://example.com/index.html" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    '192.168.1.102 - - [{timestamp}] "GET /contact.html HTTP/1.1" 200 1876 "http://example.com/about.html" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"',
    '192.168.1.103 - - [{timestamp}] "GET /products.html HTTP/1.1" 200 3421 "http://example.com/index.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '192.168.1.104 - - [{timestamp}] "GET /api/status HTTP/1.1" 200 567 "-" "curl/7.68.0"',
    '192.168.1.105 - - [{timestamp}] "POST /api/users HTTP/1.1" 201 234 "-" "PostmanRuntime/7.29.0"',
    
    # Malicious requests
    '203.0.113.45 - - [{timestamp}] "GET /admin/../../etc/passwd HTTP/1.1" 404 512 "-" "python-requests/2.28.0"',
    '198.51.100.23 - - [{timestamp}] "GET /search.php?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 2341 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '198.51.100.23 - - [{timestamp}] "GET /page.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 2341 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '198.51.100.30 - - [{timestamp}] "GET /admin/ HTTP/1.1" 404 512 "-" "Nikto/2.1.6"',
    '198.51.100.30 - - [{timestamp}] "GET /phpmyadmin/ HTTP/1.1" 404 512 "-" "sqlmap/1.4.7"',
    '198.51.100.23 - - [{timestamp}] "GET /search.php?cmd=ls;cat%20/etc/passwd HTTP/1.1" 200 2341 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '10.0.0.50 - - [{timestamp}] "POST /login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0 (X11; Linux x86_64)"',
    '203.0.113.45 - - [{timestamp}] "GET /.git/config HTTP/1.1" 404 512 "-" "python-requests/2.28.0"',
    '198.51.100.30 - - [{timestamp}] "GET /backup/ HTTP/1.1" 404 512 "-" "Nmap Scripting Engine"',
]


def generate_timestamp():
    """Generate current timestamp in Apache log format"""
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


def simulate_logs(output_file: str, interval: float = 2.0, count: int = 50):
    """
    Simulate real-time log generation
    
    Args:
        output_file: Path to output log file
        interval: Seconds between log entries
        count: Number of entries to generate (0 = infinite)
    """
    # Ensure output directory exists
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Starting log simulation...")
    print(f"[*] Writing to: {output_file}")
    print(f"[*] Interval: {interval} seconds")
    print(f"[*] Count: {'Infinite' if count == 0 else count}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    try:
        with open(output_file, 'a', encoding='utf-8') as f:
            entries_written = 0
            
            while count == 0 or entries_written < count:
                # Pick random log entry
                log_template = random.choice(SAMPLE_LOGS)
                
                # Insert current timestamp
                log_entry = log_template.format(timestamp=generate_timestamp())
                
                # Write to file
                f.write(log_entry + '\n')
                f.flush()  # Force write to disk
                
                entries_written += 1
                
                # Determine entry type for display
                entry_type = "THREAT" if any(x in log_entry for x in ['script', 'OR', 'passwd', 'sqlmap', 'Nikto', 'Nmap', '401']) else "NORMAL"
                color = '\033[91m' if entry_type == "THREAT" else '\033[92m'
                reset = '\033[0m'
                
                print(f"{color}[{entries_written}] {entry_type:6}{reset} - {log_entry[:80]}...")
                
                # Wait before next entry
                time.sleep(interval)
    
    except KeyboardInterrupt:
        print(f"\n[*] Simulation stopped. Generated {entries_written} entries.")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Simulate Apache log entries for testing real-time monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate logs every 2 seconds (default)
  python simulate_logs.py
  
  # Fast generation (1 entry per second)
  python simulate_logs.py -i 1
  
  # Generate exactly 20 entries
  python simulate_logs.py -c 20
  
  # Slow generation with custom output
  python simulate_logs.py -i 5 -o custom.log
  
  # Use with real-time monitor (2 terminals):
  Terminal 1: python simulate_logs.py -i 1
  Terminal 2: python main.py --monitor data/sample_logs/live.log --detect-threats
"""
    )
    
    parser.add_argument(
        '-o', '--output',
        default='data/sample_logs/live.log',
        help='Output log file (default: data/sample_logs/live.log)'
    )
    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=2.0,
        help='Interval between entries in seconds (default: 2.0)'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of entries to generate (0 = infinite, default: 0)'
    )
    
    args = parser.parse_args()
    
    simulate_logs(args.output, args.interval, args.count)


if __name__ == '__main__':
    main()