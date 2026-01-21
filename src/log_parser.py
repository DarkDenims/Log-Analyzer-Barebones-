"""
Apache Web Server Log Parser
Parses Apache access logs and extracts key information
"""

import re
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict, Counter
import json


class LogEntry:
    """Represents a single Apache log entry"""
    
    def __init__(self, ip: str, timestamp: str, method: str, path: str, 
                 status: int, size: int, referrer: str, user_agent: str):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.status = status
        self.size = size
        self.referrer = referrer
        self.user_agent = user_agent
    
    def __repr__(self):
        return f"LogEntry(ip={self.ip}, method={self.method}, path={self.path}, status={self.status})"


class ApacheLogParser:
    """Parses Apache Combined Log Format"""
    
    # Apache Combined Log Format regex pattern
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+) '
        r'- - '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[^"]*" '
        r'(?P<status>\d+) '
        r'(?P<size>\d+|-) '
        r'"(?P<referrer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
    )
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.entries: List[LogEntry] = []
        self.stats = defaultdict(int)
    
    def parse(self) -> List[LogEntry]:
        """Parse the log file and return list of entries"""
        print(f"[*] Parsing log file: {self.log_file}")
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                entry = self._parse_line(line.strip())
                if entry:
                    self.entries.append(entry)
                else:
                    self.stats['unparsed_lines'] += 1
        
        print(f"[+] Parsed {len(self.entries)} log entries")
        if self.stats['unparsed_lines'] > 0:
            print(f"[!] Could not parse {self.stats['unparsed_lines']} lines")
        
        return self.entries
    
    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
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
    
    def get_ip_summary(self, top_n: int = 10) -> Dict:
        """Get summary of IP addresses"""
        ip_counter = Counter(entry.ip for entry in self.entries)
        return {
            'total_unique_ips': len(ip_counter),
            'top_ips': ip_counter.most_common(top_n)
        }
    
    def get_status_summary(self) -> Dict:
        """Get summary of HTTP status codes"""
        status_counter = Counter(entry.status for entry in self.entries)
        return dict(status_counter)
    
    def get_path_summary(self, top_n: int = 10) -> Dict:
        """Get summary of requested paths"""
        path_counter = Counter(entry.path for entry in self.entries)
        return {
            'total_unique_paths': len(path_counter),
            'top_paths': path_counter.most_common(top_n)
        }
    
    def get_404_errors(self) -> List[LogEntry]:
        """Get all 404 errors (potential scanning activity)"""
        return [entry for entry in self.entries if entry.status == 404]
    
    def get_time_range(self) -> Dict:
        """Get the time range of logs"""
        if not self.entries:
            return {'start': None, 'end': None}
        
        return {
            'start': self.entries[0].timestamp,
            'end': self.entries[-1].timestamp,
            'total_entries': len(self.entries)
        }
    
    def generate_summary_report(self) -> Dict:
        """Generate a comprehensive summary report"""
        return {
            'time_range': self.get_time_range(),
            'ip_summary': self.get_ip_summary(),
            'status_summary': self.get_status_summary(),
            'path_summary': self.get_path_summary(),
            'total_404s': len(self.get_404_errors())
        }
    
    def export_to_json(self, output_file: str):
        """Export summary report to JSON"""
        report = self.generate_summary_report()
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report exported to {output_file}")


def main():
    """Main entry point for testing"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    parser = ApacheLogParser(log_file)
    parser.parse()
    
    # Print summary
    print("\n" + "="*50)
    print("APACHE LOG ANALYSIS SUMMARY")
    print("="*50)
    
    time_range = parser.get_time_range()
    print(f"\nTime Range: {time_range['start']} to {time_range['end']}")
    print(f"Total Entries: {time_range['total_entries']}")
    
    ip_summary = parser.get_ip_summary()
    print(f"\nUnique IPs: {ip_summary['total_unique_ips']}")
    print("\nTop 10 IPs:")
    for ip, count in ip_summary['top_ips']:
        print(f"  {ip:<20} {count:>6} requests")
    
    print("\nStatus Code Distribution:")
    for status, count in sorted(parser.get_status_summary().items()):
        print(f"  {status}: {count}")
    
    print(f"\nTotal 404 Errors: {len(parser.get_404_errors())}")
    
    # Export if requested
    if len(sys.argv) > 2 and sys.argv[2] == '--export':
        parser.export_to_json('output/log_analysis.json')


if __name__ == '__main__':
    main()