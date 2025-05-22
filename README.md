# Network Analysis and Security Toolkit

## 🌐 Overview

A comprehensive suite of network analysis and security tools providing real-time monitoring, port scanning, and network diagnostics capabilities.

## 🛠️ Tools Included

1. **Network Connections Analyzer**
   - Real-time interface monitoring and statistics
   - Historical data tracking with threshold-based alerting
   - Multi-interface and multi-protocol support

2. **Industrial-Grade Port Scanner**
   - Multi-protocol scanning (TCP/UDP/ICMP)
   - Flexible target specification (IP ranges, CIDR, hostnames)
   - Service detection and banner grabbing

3. **Simple Port Scanner**
   - Fast TCP port scanning with banner grabbing
   - Multithreaded architecture for performance
   - Real-time scan statistics

## ✨ Key Features

- **Comprehensive Monitoring**:
  - Track error rates, drop rates, and bandwidth usage
  - Connectivity checks for LAN and internet
  - Configurable alert thresholds

- **Advanced Scanning**:
  - Multiple scanning protocols
  - Customizable timeouts and retries
  - Rate limiting controls
  - Detailed output in CSV/JSON formats

- **Performance Optimization**:
  - Multithreaded operation
  - Configurable worker pools
  - Efficient resource utilization

## 🚀 Usage

### Network Analysis
```bash
# Live monitoring
python network_analysis.py -m 60 -i 5

# Generate report
python network_analysis.py -r
```

### Port Scanning
```bash
# Industrial scanner
python port_scanner.py 192.168.1.0/24 1-1024 -p tcp,udp

# Simple TCP scanner
python simple_scanner.py 10.0.0.1 20 100 -b -j 200
```

## ⚙️ Configuration

All tools support configuration via INI files:
- Monitoring intervals
- Thread/worker counts
- Alert thresholds
- Logging levels
- Output formats

## 📊 Output Options

- Console display with summary tables
- JSON reports for programmatic processing
- CSV exports for spreadsheet analysis
- Persistent logging to files

## 📜 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided **"as is"** without any warranty of any kind. It is intended for educational, personal, or professional use in environments where validation and review are standard.

**Use in production systems is at your own risk.**

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

**Important Legal Notice:**
- These tools should only be used on networks you own or have explicit permission to test
- Unauthorized scanning/monitoring may violate laws and policies
- Tools are provided for educational and authorized security purposes only

This software is provided "as is" without warranty. The developers are not responsible for any misuse or unauthorized access. **Use at your own risk and always obtain proper authorization.**

**For all tools:**
- Designed for professional and educational use
- Not guaranteed to be bug-free
- Users are responsible for complying with all applicable laws
- Always validate in test environments before production use
