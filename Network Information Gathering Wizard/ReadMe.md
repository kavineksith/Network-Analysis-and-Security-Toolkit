# 🛰️ Network Analyzer

A powerful, configurable, and multithreaded network analysis tool designed for real-time monitoring, reporting, and alerting. Built for developers, sysadmins, and security professionals who need granular visibility into network interfaces and performance metrics.

## 🚀 Features

* ✅ **Real-time Monitoring** of all active network interfaces
* 🧠 **Historical Data Tracking** for long-term trends
* 🔔 **Threshold-Based Alerting** for error rates, drop rates, and bandwidth usage
* ⚡ **Multithreaded Operation** for performance and scalability
* 🛠️ **Customizable Configuration** via `.ini` file
* 📡 **Connectivity Checks** (LAN, Internet)
* 📊 **Detailed Reports** in JSON format
* 🧱 Built using `psutil`, `concurrent.futures`, and `argparse`

## 🛠️ Usage

```bash
python3 network_analyzer.py [OPTIONS]
```

### Common Options

| Option           | Description                                                       |
| ---------------- | ----------------------------------------------------------------- |
| `-m, --monitor`  | Run in monitoring mode for the specified duration (seconds)       |
| `-i, --interval` | Interval between data collection during monitoring                |
| `-r, --report`   | Generate and display a JSON network report                        |
| `-c, --config`   | Use a custom configuration file (default: `network_analyzer.ini`) |
| `-v, --verbose`  | Enable verbose/debug logging                                      |

### Examples

Monitor for 60 seconds with a 5-second interval:

```bash
python3 network_analyzer.py -m 60 -i 5
```

Generate a full JSON report:

```bash
python3 network_analyzer.py -r
```

Use a custom config file and run in verbose mode:

```bash
python3 network_analyzer.py -c my_config.ini -v -r
```

## ⚙️ Configuration

The tool reads from `network_analyzer.ini` by default. You can override settings like:

```ini
[DEFAULT]
log_level = DEBUG
monitor_interval = 5
history_size = 1000
max_workers = 5
alert_thresholds = {"error_rate": 0.01, "drop_rate": 0.01, "bandwidth_usage": 0.8}
```

## 📋 Output

### Logs

All logs are saved to `network_analysis.log`.

### Report Structure (via `--report`)

```json
{
  "timestamp": "2025-05-15T10:32:00",
  "connectivity": {
    "localhost": "CONNECTED",
    "internet": "CONNECTED"
  },
  "interfaces": {
    "eth0": {
      "name": "eth0",
      "is_up": true,
      "speed": 1000,
      "mtu": 1500,
      "addresses": [...]
    }
  },
  "current_stats": {
    "eth0": {
      "bytes_sent": 123456,
      "bytes_recv": 654321,
      ...
    }
  },
  "alerts": [
    {
      "message": "High packet drop rate on eth0: 2.00%",
      "level": "WARNING",
      ...
    }
  ],
  "history_size": 60
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **educational, administrative, and diagnostic purposes** only. Misuse of network analysis tools on unauthorized systems may violate laws or terms of service. Use responsibly and with proper permissions.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
