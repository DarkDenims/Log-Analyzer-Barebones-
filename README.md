# Apache Web Server Log Analyzer

A Python-based tool for analyzing Apache web server access logs to identify security threats, suspicious activities, and generate insights.

## 🎯 Project Overview

This tool helps SOC analysts detect:
- Suspicious IP addresses and potential attackers
- SQL injection attempts
- XSS (Cross-Site Scripting) attacks
- Brute force attempts
- Unusual traffic patterns
- 404 errors and scanning activities

## 📁 Project Structure

```
log-analyzer/
├── README.md
├── requirements.txt
├── .gitignore
├── main.py
├── src/
│   ├── __init__.py
│   ├── log_parser.py
│   ├── threat_detector.py
│   └── report_generator.py
├── data/
│   └── sample_logs/
│       └── access.log
├── output/
│   └── .gitkeep
└── tests/
    └── test_log_parser.py
```

## 🚀 Features

- **Log Parsing**: Parse Apache Combined Log Format
- **Threat Detection**: Identify common attack patterns
- **IP Analysis**: Track suspicious IP addresses
- **Statistical Reports**: Generate insights from log data
- **Export Results**: Save findings to JSON/CSV/HTML/PDF

## 📋 Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: For PDF generation, install wkhtmltopdf
# Windows: Download from https://wkhtmltopdf.org/downloads.html
# macOS: brew install wkhtmltopdf
# Linux: sudo apt-get install wkhtmltopdf
```

## 💻 Usage

```bash
# Basic usage
python main.py data/sample_logs/access.log

# With threat detection
python main.py data/sample_logs/access.log --detect-threats

# Auto-generate filename with timestamp (saves to output/Log-Analysis-YYYY-MM-DD_HH-MM-SS.json)
python main.py data/sample_logs/access.log --detect-threats --format json

# Specify custom filename
python main.py data/sample_logs/access.log --detect-threats --output output/report.json

# Generate HTML report with auto-filename
python main.py data/sample_logs/access.log --detect-threats --format html

# Generate PDF report (requires wkhtmltopdf)
python main.py data/sample_logs/access.log --detect-threats --format pdf

# Generate CSV report (threats) with auto-filename
python main.py data/sample_logs/access.log --detect-threats --format csv

# Generate CSV report (top IPs) with custom name
python main.py data/sample_logs/access.log --output output/ips.csv --format csv --csv-type ips

# Custom thresholds with auto-generated PDF
python main.py data/sample_logs/access.log --detect-threats \
  --brute-force-threshold 3 \
  --scanning-threshold 5 \
  --format pdf
```

## 📊 Sample Output

```
=== Apache Log Analysis Report ===
Total Requests: 1,234
Unique IPs: 156
Time Range: 2024-01-15 to 2024-01-19

Top 5 IPs:
1. 192.168.1.100 - 245 requests
2. 10.0.0.50 - 189 requests

Threats Detected:
- SQL Injection attempts: 12
- XSS attempts: 5
- Suspicious 404s: 34
```

## 🧪 Testing

```bash
python -m pytest tests/
```

## 🛠️ Development Roadmap

### Phase 1: Core Functionality ✅
- [x] Basic log parsing with regex
- [x] Apache Combined Log Format support
- [x] Threat detection (SQL injection, XSS, path traversal)
- [x] CLI interface with argparse
- [x] JSON export functionality

### Phase 2: Enhanced Detection 🔄
- [x] Improve brute force detection accuracy
- [x] Add command injection detection
- [x] Configurable threat thresholds
- [ ] Detect credential stuffing attacks
- [ ] User-Agent based threat detection

### Phase 3: Real-Time Capabilities 🎯
- [ ] Real-time log monitoring (tail -f equivalent)
- [ ] Alert notifications (email/Slack/Discord)
- [ ] Dashboard web interface
- [ ] Live threat feed

### Phase 4: Integration & Automation 🔗
- [ ] SIEM integration (Splunk, ELK Stack)
- [x] CSV export for spreadsheet analysis
- [x] PDF export for executive reports
- [ ] Automated report generation
- [ ] Integration with threat intelligence feeds
- [ ] API endpoint for programmatic access

### Phase 5: Advanced Analytics 🚀
- [ ] Geolocation IP mapping
- [ ] Attack pattern visualization
- [ ] Historical trend analysis
- [ ] Traffic heatmaps
- [ ] Automated threat scoring

## 📖 Learning Resources

- [Apache Log Format Documentation](https://httpd.apache.org/docs/current/logs.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Log-Analysis-Projects-for-Beginners](https://github.com/0xrajneesh/Log-Analysis-Projects-for-Beginners/tree/main)

## 🤝 Contributing

Feel free to submit issues and pull requests!

## 📝 License

MIT License

## 👤 Author

Xavier Romano - SOC Analyst in Training