# 🔍 Simple Port Scanner

A high-performance, multithreaded port scanner written in Python. Designed for developers, network engineers, and cybersecurity professionals, this tool offers fast, flexible, and reliable scanning of TCP ports across a given range, with support for:

* ✅ **Multithreaded Scanning** for speed
* 📡 **Banner Grabbing** for service identification
* ⏱️ **Custom Timeouts** to tune network performance
* 📊 **Scan Statistics** for performance overview
* 🛡️ **Comprehensive Error Handling**

## 🚀 Features

* Scans any range of TCP ports on a target IP
* Banner grabbing (optional) to identify services
* Displays open/closed ports, response times, and banners
* Thread-safe logging with configurable concurrency
* Real-time performance and statistics reporting

## ⚙️ Usage

```bash
python3 port_scanner.py <ip_address> <start_port> <end_port> [options]
```

### Example:

```bash
python3 port_scanner.py 192.168.1.1 20 100 -b -t 1.5 -j 200
```

### Options:

| Option            | Description                              | Default |
| ----------------- | ---------------------------------------- | ------- |
| `-t`, `--timeout` | Timeout per connection attempt (seconds) | `1.0`   |
| `-j`, `--threads` | Maximum number of concurrent threads     | `100`   |
| `-b`, `--banner`  | Enable banner grabbing                   | `False` |

---

## 🧪 Sample Output

```
Scanning 192.168.1.1 ports 20-100...

Scan Results:
Target: 192.168.1.1
Port Range: 20-100
Open Ports (3): [21, 22, 80]

Detailed Open Ports:
Port     Response Time   Banner
-----------------------------------------------
21       0.0020          FTP Service Ready
22       0.0015          OpenSSH 8.4
80       0.0034          Apache/2.4.41 (Ubuntu)

Scan Statistics:
- Ports scanned: 81/81
- Open ports found: 3
- Scan duration: 0.35 seconds
- Scan speed: 231.4 ports/second
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**.
**Unauthorized scanning of networks that you do not own or have permission to test is illegal** and may result in criminal prosecution.

> 🛑 **Use responsibly.** Always obtain permission before scanning.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**