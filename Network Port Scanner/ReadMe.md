# Industrial-Grade Port Scanner

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Introduction

The Industrial-Grade Port Scanner is a powerful, multi-threaded network scanning tool designed for security professionals and network administrators. It provides comprehensive port scanning capabilities with enhanced features for reliability and performance in enterprise environments.

Key features include:
- **Multi-protocol support**: TCP, UDP, and ICMP scanning
- **High performance**: Multi-threaded architecture for fast scans
- **Flexible targeting**: Supports single IPs, hostnames, CIDR ranges, and IP ranges
- **Comprehensive results**: Includes service detection and banner grabbing
- **Configurable**: Adjustable timeouts, retries, and rate limiting
- **Multiple output formats**: CSV and JSON output options
- **Detailed logging**: Configurable log levels and file output

## Usage

### Basic Syntax

```bash
python3 port_scanner.py <targets> <ports> [options]
```

### Examples

1. **Basic TCP scan**:
   ```bash
   python3 port_scanner.py 192.168.1.1 80,443,8080-8090
   ```

2. **Scan multiple targets with UDP**:
   ```bash
   python3 port_scanner.py "192.168.1.1-10,example.com" 53,161 -p udp
   ```

3. **Full scan with JSON output**:
   ```bash
   python3 port_scanner.py 10.0.0.0/24 1-1024 -p tcp,udp -f json -o scan_results
   ```

4. **ICMP ping sweep**:
   ```bash
   python3 port_scanner.py 192.168.1.0/24 0 -p icmp
   ```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `targets` | Target IP(s), hostname(s), CIDR, or IP ranges (required) | - |
| `ports` | Port(s) to scan (required) | - |
| `-o, --output` | Output file name (without extension) | "scan_results" |
| `-f, --format` | Output format (csv, json) | csv |
| `-p, --protocols` | Protocols to scan (tcp,udp,icmp) | tcp,udp |
| `-c, --config` | Configuration file path | port_scanner.ini |
| `-v, --verbose` | Enable verbose logging | False |

### Configuration File

The scanner can be configured via `port_scanner.ini`:

```ini
[DEFAULT]
timeout = 1.0
max_threads = 50
max_retries = 2
banner_grab = True
rate_limit = 0  # requests per second (0 = no limit)
log_level = INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
output_format = csv  # csv or json
```

## Output

The scanner provides both console output and file output. The console shows a summary table:

```
Port     Proto    Service              Status     Response Time  Banner
----     -----    -------              ------     -------------  ------
80       TCP      http                Open       0.12           HTTP/1.1 200 OK...
443      TCP      https               Open       0.15           HTTP/1.1 200 OK...
```

File output includes all details in either CSV or JSON format.

## Advanced Usage

### Target Specification

Targets can be specified in multiple ways:
- Single IP: `192.168.1.1`
- Hostname: `example.com`
- CIDR notation: `10.0.0.0/24`
- IP ranges: `192.168.1.1-100`
- Comma-separated list of any combination

### Port Specification

Ports can be specified as:
- Single port: `80`
- Port range: `20-25`
- Service name: `http,https`
- Comma-separated list of any combination

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

## Disclaimer (Sumarized)

**WARNING:** Port scanning may be considered intrusive or hostile by some network administrators. 

- This tool should only be used on networks you own or have explicit permission to scan
- Unauthorized scanning may violate laws or organizational policies
- The authors assume no liability for misuse of this software
- Use responsibly and respect others' networks and privacy
