#!/usr/bin/env python3
"""
Apache Log Analyzer - Main Entry Point
Analyzes Apache logs for security threats and generates reports
"""

import argparse
import sys
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.log_parser import ApacheLogParser
from src.threat_detector import ThreatDetector


def main():
    parser = argparse.ArgumentParser(
        description='Apache Web Server Log Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
                Examples:
                # Basic analysis
                python main.py data/sample_logs/access.log
                
                # With threat detection
                python main.py data/sample_logs/access.log --detect-threats
                
                # Export to JSON
                python main.py data/sample_logs/access.log --detect-threats --output report.json
                
                # Show only threats
                python main.py data/sample_logs/access.log --detect-threats --threats-only
                """
    )
    
    parser.add_argument(
        'logfile',
        help='Path to Apache log file'
    )
    
    parser.add_argument(
        '-d', '--detect-threats',
        action='store_true',
        help='Enable threat detection'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for JSON report'
    )
    
    parser.add_argument(
        '-t', '--threats-only',
        action='store_true',
        help='Show only threat detection results'
    )
    
    parser.add_argument(
        '--top-n',
        type=int,
        default=10,
        help='Number of top items to show (default: 10)'
    )
    
    args = parser.parse_args()
    
    # Validate log file exists
    if not Path(args.logfile).exists():
        print(f"[!] Error: Log file not found: {args.logfile}")
        sys.exit(1)
    
    print("="*70)
    print("APACHE WEB SERVER LOG ANALYZER")
    print("="*70)
    print()
    
    # Parse logs
    log_parser = ApacheLogParser(args.logfile)
    entries = log_parser.parse()
    
    if not entries:
        print("[!] No valid log entries found")
        sys.exit(1)
    
    # Basic analysis (unless threats-only)
    if not args.threats_only:
        print_basic_analysis(log_parser, args.top_n)
    
    # Threat detection
    if args.detect_threats:
        print("\n" + "="*70)
        threat_detector = ThreatDetector(entries)
        threats = threat_detector.detect_all_threats()
        threat_detector.print_threat_report()
        
        # Export if requested
        if args.output:
            export_full_report(log_parser, threat_detector, args.output)
    elif args.output:
        # Export basic report only
        log_parser.export_to_json(args.output)
    
    print("\n[+] Analysis complete!")


def print_basic_analysis(log_parser, top_n):
    """Print basic log analysis"""
    # Time range
    time_range = log_parser.get_time_range()
    print(f"\n📅 TIME RANGE")
    print(f"   Start: {time_range['start']}")
    print(f"   End:   {time_range['end']}")
    print(f"   Total Entries: {time_range['total_entries']:,}")
    
    # IP summary
    ip_summary = log_parser.get_ip_summary(top_n)
    print(f"\n🌐 IP ADDRESS ANALYSIS")
    print(f"   Unique IPs: {ip_summary['total_unique_ips']}")
    print(f"\n   Top {top_n} IPs:")
    for ip, count in ip_summary['top_ips']:
        print(f"      {ip:<20} {count:>6,} requests")
    
    # Status codes
    status_summary = log_parser.get_status_summary()
    print(f"\n📊 HTTP STATUS CODES")
    for status, count in sorted(status_summary.items()):
        status_desc = get_status_description(status)
        print(f"   {status} ({status_desc}): {count:>6,}")
    
    # Path summary
    path_summary = log_parser.get_path_summary(top_n)
    print(f"\n🔗 REQUESTED PATHS")
    print(f"   Unique paths: {path_summary['total_unique_paths']}")
    print(f"\n   Top {top_n} paths:")
    for path, count in path_summary['top_paths']:
        display_path = path[:60] + '...' if len(path) > 60 else path
        print(f"      {display_path:<63} {count:>6,}")
    
    # 404 errors
    not_found = len(log_parser.get_404_errors())
    print(f"\n⚠️  404 ERRORS: {not_found:,}")


def get_status_description(status_code):
    """Get human-readable status code description"""
    descriptions = {
        200: "OK",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable"
    }
    return descriptions.get(status_code, "Unknown")


def export_full_report(log_parser, threat_detector, output_file):
    """Export comprehensive report including threats"""
    report = {
        'basic_analysis': log_parser.generate_summary_report(),
        'threat_analysis': threat_detector.get_threat_summary(),
        'threats': [
            {
                'type': t.threat_type,
                'ip': t.ip,
                'path': t.path,
                'timestamp': t.timestamp,
                'severity': t.severity,
                'description': t.description
            }
            for t in threat_detector.threats
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Full report exported to: {output_file}")


if __name__ == '__main__':
    main()