"""
Real-Time Log Monitoring Module
Monitors Apache log files for new entries and detects threats in real-time
"""

import time
import re
import sys
from pathlib import Path
from typing import Optional, Callable
from datetime import datetime

# Fix import paths - use relative imports
from .log_parser import LogEntry
from .threat_detector import ThreatDetector


class LogMonitor:
    """Monitors log files in real-time (like tail -f)"""
    
    def __init__(self, log_file: str, threat_detector_config: dict = None, alert_callback: Optional[Callable] = None):
        self.log_file = log_file
        self.threat_detector_config = threat_detector_config or {}
        self.alert_callback = alert_callback
        self.running = False
        self.total_entries = 0
        self.total_threats = 0
        
        # Apache log pattern (same as ApacheLogParser)
        self.LOG_PATTERN = re.compile(
            r'(?P<ip>[\d\.]+) '
            r'- - '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[^"]*" '
            r'(?P<status>\d+) '
            r'(?P<size>\d+|-) '
            r'"(?P<referrer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )
    
    def start(self):
        """Start monitoring the log file"""
        self.running = True
        
        print("="*70)
        print("REAL-TIME LOG MONITOR")
        print("="*70)
        print(f"Monitoring: {self.log_file}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Threat Detection: {'Enabled' if self.threat_detector_config else 'Disabled'}")
        print("\nWaiting for new log entries... (Press Ctrl+C to stop)\n")
        
        try:
            # Check if file exists, create if not
            log_path = Path(self.log_file)
            if not log_path.exists():
                print(f"[*] Log file doesn't exist yet, creating: {self.log_file}")
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.touch()
            
            # Open file and seek to end
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    
                    if line:
                        # Process new line
                        self._process_line(line.strip())
                    else:
                        # No new data, sleep briefly
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            self._shutdown()
        except FileNotFoundError:
            print(f"[!] Error: Log file not found: {self.log_file}")
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
            self._shutdown()
    
    def _process_line(self, line: str):
        """Process a single log line"""
        if not line.strip():
            return
            
        # Parse log entry
        entry = self._parse_line(line)
        
        if not entry:
            return
        
        self.total_entries += 1
        
        # Print log entry
        timestamp = datetime.now().strftime('%H:%M:%S')
        status_color = self._get_status_color(entry.status)
        reset = '\033[0m'
        
        # Truncate path for display
        display_path = entry.path[:60] if len(entry.path) <= 60 else entry.path[:57] + '...'
        
        print(f"[{timestamp}] {entry.ip:<15} {entry.method:<6} {status_color}{entry.status}{reset} {display_path}")
        
        # Check for threats if enabled
        if self.threat_detector_config.get('enabled'):
            threats = self._check_threats(entry)
            
            if threats:
                for threat in threats:
                    self.total_threats += 1
                    self._alert_threat(threat)
    
    def _get_status_color(self, status: int) -> str:
        """Get color code for HTTP status"""
        if status >= 500:
            return '\033[91m'  # Red for 5xx
        elif status >= 400:
            return '\033[93m'  # Yellow for 4xx
        elif status >= 300:
            return '\033[94m'  # Blue for 3xx
        else:
            return '\033[92m'  # Green for 2xx
    
    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into LogEntry"""
        match = self.LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        try:
            return LogEntry(
                ip=data['ip'],
                timestamp=data['timestamp'],
                method=data['method'],
                path=data['path'],
                status=int(data['status']),
                size=int(data['size']) if data['size'] != '-' else 0,
                referrer=data['referrer'],
                user_agent=data['user_agent']
            )
        except (ValueError, KeyError):
            return None
    
    def _check_threats(self, entry: LogEntry) -> list:
        """Check single entry for threats"""
        threats = []
        
        # Check pattern-based threats (no frequency needed)
        if self._check_sql_injection(entry):
            threats.append({
                'type': 'SQL_INJECTION',
                'severity': 'HIGH',
                'ip': entry.ip,
                'path': entry.path,
                'timestamp': entry.timestamp
            })
        
        if self._check_xss(entry):
            threats.append({
                'type': 'XSS',
                'severity': 'MEDIUM',
                'ip': entry.ip,
                'path': entry.path,
                'timestamp': entry.timestamp
            })
        
        if self._check_path_traversal(entry):
            threats.append({
                'type': 'PATH_TRAVERSAL',
                'severity': 'HIGH',
                'ip': entry.ip,
                'path': entry.path,
                'timestamp': entry.timestamp
            })
        
        if self._check_command_injection(entry):
            threats.append({
                'type': 'COMMAND_INJECTION',
                'severity': 'CRITICAL',
                'ip': entry.ip,
                'path': entry.path,
                'timestamp': entry.timestamp
            })
        
        if self._check_suspicious_user_agent(entry):
            threats.append({
                'type': 'SUSPICIOUS_USER_AGENT',
                'severity': 'MEDIUM',
                'ip': entry.ip,
                'path': entry.user_agent[:60],
                'timestamp': entry.timestamp
            })
        
        return threats
    
    def _check_sql_injection(self, entry: LogEntry) -> bool:
        """Check for SQL injection patterns"""
        SQL_PATTERNS = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
        ]
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in SQL_PATTERNS)
    
    def _check_xss(self, entry: LogEntry) -> bool:
        """Check for XSS patterns"""
        XSS_PATTERNS = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe",
            r"eval\(",
            r"alert\(",
        ]
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in XSS_PATTERNS)
    
    def _check_path_traversal(self, entry: LogEntry) -> bool:
        """Check for path traversal attempts"""
        PATH_TRAVERSAL_PATTERNS = [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
            r"\.\.%2f",
        ]
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in PATH_TRAVERSAL_PATTERNS)
    
    def _check_command_injection(self, entry: LogEntry) -> bool:
        """Check for command injection attempts"""
        CMD_INJECTION_PATTERNS = [
            r"[;&|]\s*(cat|ls|wget|curl|nc|bash|sh|cmd)",
            r"\$\(.*\)",
            r"`.*`",
        ]
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in CMD_INJECTION_PATTERNS)
    
    def _check_suspicious_user_agent(self, entry: LogEntry) -> bool:
        """Check for suspicious/malicious user agents"""
        SUSPICIOUS_USER_AGENTS = [
            r"nikto", r"sqlmap", r"nmap", r"masscan", r"metasploit",
            r"burp\s?suite", r"acunetix", r"nessus", r"openvas",
            r"python-requests(?!/\d)", r"curl(?!/\d)",
        ]
        user_agent = entry.user_agent.lower()
        
        if len(user_agent.strip()) == 0 or user_agent == "-":
            return True
        
        return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in SUSPICIOUS_USER_AGENTS)
    
    def _alert_threat(self, threat: dict):
        """Alert when threat is detected"""
        # Color codes for terminal
        COLORS = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[90m',       # Gray
            'RESET': '\033[0m'
        }
        
        color = COLORS.get(threat['severity'], COLORS['RESET'])
        reset = COLORS['RESET']
        
        print(f"\n{color}{'='*70}")
        print(f"🚨 THREAT DETECTED: {threat['type']}")
        print(f"{'='*70}{reset}")
        print(f"Severity: {color}{threat['severity']}{reset}")
        print(f"IP Address: {threat['ip']}")
        print(f"Timestamp: {threat['timestamp']}")
        print(f"Details: {threat['path'][:60]}")
        print(f"{color}{'='*70}{reset}\n")
        
        # Call custom alert callback if provided
        if self.alert_callback:
            self.alert_callback(threat)
    
    def _shutdown(self):
        """Clean shutdown"""
        self.running = False
        print("\n" + "="*70)
        print("MONITORING STOPPED")
        print("="*70)
        print(f"Total Entries Processed: {self.total_entries}")
        print(f"Total Threats Detected: {self.total_threats}")
        print(f"Stopped: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False


def main():
    """Test the monitor"""
    if len(sys.argv) < 2:
        print("Usage: python -m src.log_monitor <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    monitor = LogMonitor(log_file, threat_detector_config={'enabled': True})
    monitor.start()


if __name__ == '__main__':
    main()