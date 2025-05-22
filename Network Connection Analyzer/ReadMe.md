# Network Connections Analysis Tool

A comprehensive Python-based tool for monitoring, diagnosing, and reporting on network performance across multiple interfaces with configurable thresholds, logging, historical tracking, and alerting capabilities.

## 🚀 Features

* Real-time interface monitoring and statistics
* Historical data tracking for up to 1000 entries per interface
* Threshold-based alerting (error rate, drop rate, bandwidth usage)
* Multi-interface and multi-protocol support
* Gateway and connection tracking
* Configurable logging, alert sensitivity, and threading
* Generate detailed JSON reports on demand or periodically

## ⚙️ Configuration

The tool uses a configuration file (`network_manager.ini`) with the following default parameters:

```ini
[DEFAULT]
log_level = INFO
history_size = 1000
max_workers = 5
alert_thresholds = {
  "error_rate": 0.01,
  "drop_rate": 0.01,
  "bandwidth_usage": 0.8
}
```

Customize thresholds and behaviors as needed.

## 🧪 Usage

```bash
python network_analysis.py [OPTIONS]
```

### Available Options:

| Option                    | Description                                             |
| ------------------------- | ------------------------------------------------------- |
| `-c`, `--config`          | Path to configuration file (INI format)                 |
| `-r`, `--report`          | Generate a one-time network report                      |
| `-v`, `--verbose`         | Enable verbose (DEBUG) logging                          |
| `-m`, `--monitor SECONDS` | Continuously monitor network for the specified duration |

### Example: Run a live 60-second monitor with verbose output

```bash
python network_analysis.py -m 60 -v
```

### Example: Generate a single snapshot report

```bash
python network_analysis.py -r
```

## 📄 Output

Reports are structured in JSON and include:

* **Timestamp**
* **Interface stats & addresses**
* **Active network connections**
* **Default gateway information**
* **Recent alerts**
* **History length per interface**

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for **informational and diagnostic purposes only**. While it can help identify and track network issues, it **should not be used as a substitute for enterprise-grade monitoring platforms** in critical infrastructure environments. Use at your own risk.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
