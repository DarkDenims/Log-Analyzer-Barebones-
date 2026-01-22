"""
Report Generator Module
Generates various report formats from log analysis and threat detection results
"""

import json
import csv
from typing import Dict, List
from datetime import datetime
from pathlib import Path

# PDF support - optional dependency
try:
    import pdfkit
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ReportGenerator:
    """Generates reports in various formats"""
    
    def __init__(self, log_parser, threat_detector=None):
        self.log_parser = log_parser
        self.threat_detector = threat_detector
    
    def generate_json_report(self, output_file: str, include_threats: bool = True):
        """Generate comprehensive JSON report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'log_file': self.log_parser.log_file,
            'basic_analysis': self._get_basic_analysis(),
        }
        
        if include_threats and self.threat_detector:
            report['threat_analysis'] = self._get_threat_analysis()
            report['threats'] = self._get_threat_details()
        
        # Ensure output directory exists
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] JSON report exported to: {output_file}")
        return report
    
    def generate_csv_report(self, output_file: str, report_type: str = 'threats'):
        """Generate CSV report
        
        Args:
            output_file: Path to save CSV
            report_type: 'threats', 'ips', or 'paths'
        """
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        if report_type == 'threats' and self.threat_detector:
            self._generate_threats_csv(output_file)
        elif report_type == 'ips':
            self._generate_ips_csv(output_file)
        elif report_type == 'paths':
            self._generate_paths_csv(output_file)
        else:
            print(f"[!] Unknown report type: {report_type}")
            return
        
        print(f"[+] CSV report exported to: {output_file}")
    
    def generate_html_report(self, output_file: str):
        """Generate HTML report with styling"""
        html_content = self._build_html_report()
        
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] HTML report exported to: {output_file}")
    
    def generate_pdf_report(self, output_file: str):
        """Generate PDF report from HTML
        
        Requires:
            - pdfkit: pip install pdfkit
            - wkhtmltopdf: System dependency
              * Windows: https://wkhtmltopdf.org/downloads.html
              * macOS: brew install wkhtmltopdf
              * Linux: sudo apt-get install wkhtmltopdf
        """
        if not PDF_AVAILABLE:
            print("[!] Error: pdfkit not installed. Install with: pip install pdfkit")
            print("[!] Also ensure wkhtmltopdf is installed on your system")
            return
        
        try:
            # Generate HTML content
            html_content = self._build_html_report()
            
            # Ensure output directory exists
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            # PDF generation options for better formatting
            options = {
                'page-size': 'Letter',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            # Convert HTML to PDF
            pdfkit.from_string(html_content, output_file, options=options)
            print(f"[+] PDF report exported to: {output_file}")
            
        except OSError as e:
            if "wkhtmltopdf" in str(e).lower():
                print("[!] Error: wkhtmltopdf not found on system")
                print("[!] Please install wkhtmltopdf:")
                print("    Windows: https://wkhtmltopdf.org/downloads.html")
                print("    macOS: brew install wkhtmltopdf")
                print("    Linux: sudo apt-get install wkhtmltopdf")
            else:
                print(f"[!] Error generating PDF: {e}")
        except Exception as e:
            print(f"[!] Error generating PDF: {e}")
    
    def generate_text_summary(self) -> str:
        """Generate plain text summary for console output"""
        lines = []
        lines.append("=" * 70)
        lines.append("APACHE LOG ANALYSIS SUMMARY")
        lines.append("=" * 70)
        
        # Time range
        time_range = self.log_parser.get_time_range()
        lines.append(f"\n📅 TIME RANGE")
        lines.append(f"   Start: {time_range['start']}")
        lines.append(f"   End:   {time_range['end']}")
        lines.append(f"   Total Entries: {time_range['total_entries']:,}")
        
        # IP summary
        ip_summary = self.log_parser.get_ip_summary(10)
        lines.append(f"\n🌐 IP ADDRESS ANALYSIS")
        lines.append(f"   Unique IPs: {ip_summary['total_unique_ips']}")
        lines.append(f"\n   Top 10 IPs:")
        for ip, count in ip_summary['top_ips']:
            lines.append(f"      {ip:<20} {count:>6,} requests")
        
        # Status codes
        status_summary = self.log_parser.get_status_summary()
        lines.append(f"\n📊 HTTP STATUS CODES")
        for status, count in sorted(status_summary.items()):
            status_desc = self._get_status_description(status)
            lines.append(f"   {status} ({status_desc}): {count:>6,}")
        
        # 404 errors
        not_found = len(self.log_parser.get_404_errors())
        lines.append(f"\n⚠️  404 ERRORS: {not_found:,}")
        
        # Threats if available
        if self.threat_detector:
            lines.append("\n" + "=" * 70)
            lines.append("THREAT DETECTION SUMMARY")
            lines.append("=" * 70)
            
            summary = self.threat_detector.get_threat_summary()
            lines.append(f"\n🚨 Total Threats: {summary['total_threats']}")
            
            lines.append("\nThreats by Type:")
            for threat_type, count in sorted(summary['threats_by_type'].items()):
                lines.append(f"   {threat_type:<25} {count:>4}")
            
            lines.append("\nTop Malicious IPs:")
            for ip, count in summary['top_malicious_ips'][:5]:
                lines.append(f"   {ip:<20} {count:>4} threats")
        
        return "\n".join(lines)
    
    # Private helper methods
    
    def _get_basic_analysis(self) -> Dict:
        """Get basic log analysis data"""
        return {
            'time_range': self.log_parser.get_time_range(),
            'ip_summary': self.log_parser.get_ip_summary(),
            'status_summary': self.log_parser.get_status_summary(),
            'path_summary': self.log_parser.get_path_summary(),
            'total_404s': len(self.log_parser.get_404_errors())
        }
    
    def _get_threat_analysis(self) -> Dict:
        """Get threat detection summary"""
        return self.threat_detector.get_threat_summary()
    
    def _get_threat_details(self) -> List[Dict]:
        """Get detailed threat information"""
        return [
            {
                'type': t.threat_type,
                'ip': t.ip,
                'path': t.path,
                'timestamp': t.timestamp,
                'severity': t.severity,
                'description': t.description
            }
            for t in self.threat_detector.threats
        ]
    
    def _generate_threats_csv(self, output_file: str):
        """Generate CSV of detected threats"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Threat Type', 'Severity', 'IP Address', 'Path', 'Description'])
            
            for threat in self.threat_detector.threats:
                writer.writerow([
                    threat.timestamp,
                    threat.threat_type,
                    threat.severity,
                    threat.ip,
                    threat.path[:100],  # Truncate long paths
                    threat.description
                ])
    
    def _generate_ips_csv(self, output_file: str):
        """Generate CSV of IP statistics"""
        ip_summary = self.log_parser.get_ip_summary(100)  # Top 100 IPs
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address', 'Request Count', 'Threat Count'])
            
            threat_counts = {}
            if self.threat_detector:
                threat_counts = dict(self.threat_detector.ip_threat_count)
            
            for ip, count in ip_summary['top_ips']:
                writer.writerow([
                    ip,
                    count,
                    threat_counts.get(ip, 0)
                ])
    
    def _generate_paths_csv(self, output_file: str):
        """Generate CSV of requested paths"""
        path_summary = self.log_parser.get_path_summary(100)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Path', 'Request Count'])
            
            for path, count in path_summary['top_paths']:
                writer.writerow([path, count])
    
    def _build_html_report(self) -> str:
        """Build HTML report with styling"""
        basic = self._get_basic_analysis()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Apache Log Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .summary-box {{
            background-color: #ecf0f1;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .threat-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .threat-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .threat-low {{
            color: #95a5a6;
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            font-size: 18px;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .stat-value {{
            color: #2c3e50;
            font-weight: bold;
            font-size: 24px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Apache Log Analysis Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary-box">
            <h2>📊 Summary Statistics</h2>
            <div class="stat">
                <div class="stat-label">Total Entries</div>
                <div class="stat-value">{basic['time_range']['total_entries']:,}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Unique IPs</div>
                <div class="stat-value">{basic['ip_summary']['total_unique_ips']}</div>
            </div>
            <div class="stat">
                <div class="stat-label">404 Errors</div>
                <div class="stat-value">{basic['total_404s']}</div>
            </div>
"""
        
        if self.threat_detector:
            threat_summary = self._get_threat_analysis()
            html += f"""
            <div class="stat">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-value threat-high">{threat_summary['total_threats']}</div>
            </div>
"""
        
        html += """
        </div>
        
        <h2>🌐 Top IP Addresses</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Requests</th>
            </tr>
"""
        
        for ip, count in basic['ip_summary']['top_ips'][:10]:
            html += f"<tr><td>{ip}</td><td>{count:,}</td></tr>\n"
        
        html += "</table>"
        
        # Threats table if available
        if self.threat_detector and self.threat_detector.threats:
            html += """
        <h2>🚨 Detected Threats</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>IP Address</th>
                <th>Timestamp</th>
            </tr>
"""
            
            for threat in self.threat_detector.threats[:20]:  # Top 20 threats
                severity_class = f"threat-{threat.severity.lower()}"
                html += f"""
            <tr>
                <td>{threat.threat_type}</td>
                <td class="{severity_class}">{threat.severity}</td>
                <td>{threat.ip}</td>
                <td>{threat.timestamp}</td>
            </tr>
"""
            
            html += "</table>"
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _get_status_description(self, status_code: int) -> str:
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