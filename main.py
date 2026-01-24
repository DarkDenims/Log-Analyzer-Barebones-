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
from src.report_generator import ReportGenerator
from src.log_monitor import LogMonitor


def generate_default_filename(format_type: str) -> str:
    """Generate default filename with timestamp"""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"output/Log-Analysis-{timestamp}.{format_type}"


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
  
  # Auto-generate timestamped JSON report
  python main.py data/sample_logs/access.log --detect-threats --format json
  Output: output/Log-Analysis-2024-01-22_14-30-45.json
  
  # Auto-generate timestamped PDF report
  python main.py data/sample_logs/access.log --detect-threats --format pdf
  Output: output/Log-Analysis-2024-01-22_14-30-45.pdf
  
  # Custom filename
  python main.py data/sample_logs/access.log --detect-threats --output custom_report.json
  
  # Show only threats with auto-generated report
  python main.py data/sample_logs/access.log --detect-threats --threats-only --format html
        """
    )
    
    parser.add_argument(
        'logfile',
        help='Path to Apache log file'
    )
    
    parser.add_argument(
        '-m', '--monitor',
        action='store_true',
        help='Monitor log file in real-time (like tail -f)'
    )
    
    parser.add_argument(
        '-d', '--detect-threats',
        action='store_true',
        help='Enable threat detection'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for report (default: auto-generated with timestamp). Supports .json, .csv, .html, .pdf'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'html', 'pdf'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--csv-type',
        choices=['threats', 'ips', 'paths'],
        default='threats',
        help='CSV report type: threats, ips, or paths (default: threats)'
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
    
    parser.add_argument(
        '--brute-force-threshold',
        type=int,
        default=5,
        help='Number of failed attempts to trigger brute force alert (default: 5)'
    )
    
    parser.add_argument(
        '--scanning-threshold',
        type=int,
        default=10,
        help='Number of 404s to trigger scanning alert (default: 10)'
    )
    
    parser.add_argument(
        '--credential-stuffing-threshold',
        type=int,
        default=5,
        help='Number of different usernames to trigger credential stuffing alert (default: 5)'
    )
    
    args = parser.parse_args()
    
    # Validate log file exists
    if not Path(args.logfile).exists():
        print(f"[!] Error: Log file not found: {args.logfile}")
        sys.exit(1)
    
    # Real-time monitoring mode
    if args.monitor:
        threat_config = {'enabled': True} if args.detect_threats else None
        monitor = LogMonitor(args.logfile, threat_detector_config=threat_config)
        monitor.start()
        return
    
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
    threat_detector = None
    if args.detect_threats:
        print("\n" + "="*70)
        threat_detector = ThreatDetector(
            entries, 
            brute_force_threshold=args.brute_force_threshold,
            scanning_threshold=args.scanning_threshold,
            credential_stuffing_threshold=args.credential_stuffing_threshold
        )
        threats = threat_detector.detect_all_threats()
        threat_detector.print_threat_report()
    
    # Generate reports
    if args.output or args.format:
        report_gen = ReportGenerator(log_parser, threat_detector)
        
        # Generate default filename if not provided
        output_file = args.output
        if not output_file:
            output_file = generate_default_filename(args.format)
            print(f"\n[*] No output file specified, using: {output_file}")
        
        if args.format == 'json':
            report_gen.generate_json_report(
                output_file, 
                include_threats=(threat_detector is not None)
            )
        elif args.format == 'csv':
            report_gen.generate_csv_report(output_file, args.csv_type)
        elif args.format == 'html':
            report_gen.generate_html_report(output_file)
        elif args.format == 'pdf':
            report_gen.generate_pdf_report(output_file)
    
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


if __name__ == '__main__':
    main()