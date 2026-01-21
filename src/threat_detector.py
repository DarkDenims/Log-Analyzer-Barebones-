"""
Threat Detection Module
Identifies common attack patterns in Apache logs
"""

import re
from typing import List, Dict
from collections import defaultdict, Counter
from dataclasses import dataclass


@dataclass
class ThreatAlert:
    """Represents a detected threat"""
    threat_type: str
    ip: str
    path: str
    timestamp: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str


class ThreatDetector:
    """Detects common web attacks in Apache logs"""
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Typical SQLi
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # OR statements
        r"((\%27)|(\'))union",  # UNION queries
        r"exec(\s|\+)+(s|x)p\w+",  # Stored procedures
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
        r"eval\(",
        r"alert\(",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.%2f",
    ]
    
    # Command injection patterns
    CMD_INJECTION_PATTERNS = [
        r"[;&|]\s*(cat|ls|wget|curl|nc|bash|sh|cmd)",
        r"\$\(.*\)",
        r"`.*`",
    ]
    
    def __init__(self, entries):
        self.entries = entries
        self.threats: List[ThreatAlert] = []
        self.ip_threat_count = Counter()
        
    def detect_all_threats(self) -> List[ThreatAlert]:
        """Run all threat detection methods"""
        print("[*] Running threat detection...")
        
        for entry in self.entries:
            # SQL Injection
            if self._check_sql_injection(entry):
                self.threats.append(ThreatAlert(
                    threat_type="SQL_INJECTION",
                    ip=entry.ip,
                    path=entry.path,
                    timestamp=entry.timestamp,
                    severity="HIGH",
                    description="Possible SQL injection attempt detected"
                ))
                self.ip_threat_count[entry.ip] += 1
            
            # XSS
            if self._check_xss(entry):
                self.threats.append(ThreatAlert(
                    threat_type="XSS",
                    ip=entry.ip,
                    path=entry.path,
                    timestamp=entry.timestamp,
                    severity="MEDIUM",
                    description="Possible XSS attempt detected"
                ))
                self.ip_threat_count[entry.ip] += 1
            
            # Path Traversal
            if self._check_path_traversal(entry):
                self.threats.append(ThreatAlert(
                    threat_type="PATH_TRAVERSAL",
                    ip=entry.ip,
                    path=entry.path,
                    timestamp=entry.timestamp,
                    severity="HIGH",
                    description="Path traversal attempt detected"
                ))
                self.ip_threat_count[entry.ip] += 1
            
            # Command Injection
            if self._check_command_injection(entry):
                self.threats.append(ThreatAlert(
                    threat_type="COMMAND_INJECTION",
                    ip=entry.ip,
                    path=entry.path,
                    timestamp=entry.timestamp,
                    severity="CRITICAL",
                    description="Command injection attempt detected"
                ))
                self.ip_threat_count[entry.ip] += 1
        
        # Detect brute force
        self._detect_brute_force()
        
        # Detect scanning activity
        self._detect_scanning()
        
        print(f"[+] Detected {len(self.threats)} potential threats")
        return self.threats
    
    def _check_sql_injection(self, entry) -> bool:
        """Check for SQL injection patterns"""
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.SQL_PATTERNS)
    
    def _check_xss(self, entry) -> bool:
        """Check for XSS patterns"""
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.XSS_PATTERNS)
    
    def _check_path_traversal(self, entry) -> bool:
        """Check for path traversal attempts"""
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.PATH_TRAVERSAL_PATTERNS)
    
    def _check_command_injection(self, entry) -> bool:
        """Check for command injection attempts"""
        path = entry.path.lower()
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.CMD_INJECTION_PATTERNS)
    
    def _detect_brute_force(self):
        """Detect potential brute force attempts"""
        # Count failed logins per IP (401/403 status codes)
        failed_attempts = defaultdict(list)
        
        for entry in self.entries:
            if entry.status in [401, 403]:
                failed_attempts[entry.ip].append(entry)
        
        # Flag IPs with more than 10 failed attempts
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= 10:
                self.threats.append(ThreatAlert(
                    threat_type="BRUTE_FORCE",
                    ip=ip,
                    path=f"{len(attempts)} failed attempts",
                    timestamp=attempts[0].timestamp,
                    severity="HIGH",
                    description=f"Possible brute force attack: {len(attempts)} failed auth attempts"
                ))
                self.ip_threat_count[ip] += 1
    
    def _detect_scanning(self):
        """Detect scanning activity (lots of 404s from same IP)"""
        not_found = defaultdict(list)
        
        for entry in self.entries:
            if entry.status == 404:
                not_found[entry.ip].append(entry)
        
        # Flag IPs with more than 20 404s
        for ip, attempts in not_found.items():
            if len(attempts) >= 20:
                self.threats.append(ThreatAlert(
                    threat_type="SCANNING",
                    ip=ip,
                    path=f"{len(attempts)} 404 errors",
                    timestamp=attempts[0].timestamp,
                    severity="MEDIUM",
                    description=f"Possible scanning activity: {len(attempts)} not found errors"
                ))
                self.ip_threat_count[ip] += 1
    
    def get_threat_summary(self) -> Dict:
        """Generate threat summary report"""
        threat_types = Counter(t.threat_type for t in self.threats)
        severity_counts = Counter(t.severity for t in self.threats)
        
        return {
            'total_threats': len(self.threats),
            'threats_by_type': dict(threat_types),
            'threats_by_severity': dict(severity_counts),
            'top_malicious_ips': self.ip_threat_count.most_common(10),
        }
    
    def print_threat_report(self):
        """Print a formatted threat report"""
        summary = self.get_threat_summary()
        
        print("\n" + "="*60)
        print("THREAT DETECTION REPORT")
        print("="*60)
        
        print(f"\nTotal Threats Detected: {summary['total_threats']}")
        
        print("\nThreats by Type:")
        for threat_type, count in sorted(summary['threats_by_type'].items()):
            print(f"  {threat_type:<25} {count:>4}")
        
        print("\nThreats by Severity:")
        for severity, count in sorted(summary['threats_by_severity'].items()):
            print(f"  {severity:<25} {count:>4}")
        
        print("\nTop 10 Malicious IPs:")
        for ip, count in summary['top_malicious_ips']:
            print(f"  {ip:<20} {count:>4} threats")
        
        # Show sample threats
        if self.threats:
            print("\nSample Threats (first 5):")
            for threat in self.threats[:5]:
                print(f"\n  [{threat.severity}] {threat.threat_type}")
                print(f"  IP: {threat.ip}")
                print(f"  Path: {threat.path[:80]}")
                print(f"  Time: {threat.timestamp}")