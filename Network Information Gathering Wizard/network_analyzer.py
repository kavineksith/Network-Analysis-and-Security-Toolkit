#!/usr/bin/env python3
"""
Industrial-Grade Network Information Gathering Wizard with:
- Asynchronous monitoring capabilities
- Historical data tracking via generators
- Alerting system
- Multi-interface support
- Configurable thresholds
- Enhanced error handling with custom exceptions
- Dunder methods for pythonic usage
"""

import json
import psutil
import socket
import logging
import time
import sys
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Generator
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum, auto
import configparser
import argparse
from concurrent.futures import ThreadPoolExecutor

# Constants
DEFAULT_CONFIG_FILE = "network_analyzer.ini"
LOG_FILE = "network_analysis.log"
MAX_WORKERS = 5
MONITOR_INTERVAL = 5  # seconds
HISTORY_SIZE = 1000

class NetworkGatheringError(Exception):
    """Base exception for Network Gathering Wizard"""
    pass

class ConnectionStatus(Enum):
    CONNECTED = auto()
    DISCONNECTED = auto()
    DEGRADED = auto()

class AlertLevel(Enum):
    INFO = auto()
    WARNING = auto()
    CRITICAL = auto()

@dataclass
class NetworkStats:
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int
    timestamp: float = field(default_factory=time.time)

@dataclass
class NetworkAlert:
    message: str
    level: AlertLevel
    threshold: Optional[float] = None
    current_value: Optional[float] = None
    timestamp: float = field(default_factory=time.time)

@dataclass
class InterfaceInfo:
    name: str
    is_up: bool
    speed: float
    mtu: int
    addresses: List[Dict[str, str]]

class NetworkAnalyzer:
    def __init__(self, config_file: str = DEFAULT_CONFIG_FILE):
        self.config = self._load_config(config_file)
        self._setup_logging()
        self.history: List[NetworkStats] = []
        self.alerts: List[NetworkAlert] = []
        self.interface_stats: Dict[str, List[NetworkStats]] = {}
        self._executor = ThreadPoolExecutor(max_workers=int(self.config['DEFAULT']['max_workers']))
        self._init_history()

    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._executor.shutdown(wait=False)

    def __len__(self) -> int:
        """Return the number of global history records"""
        return len(self.history)
        
    def __iter__(self):
        """Yield history records chronologically"""
        return iter(self.history)

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'log_level': 'INFO',
            'monitor_interval': str(MONITOR_INTERVAL),
            'history_size': str(HISTORY_SIZE),
            'max_workers': str(MAX_WORKERS),
            'alert_thresholds': json.dumps({
                'error_rate': 0.01,
                'drop_rate': 0.01,
                'bandwidth_usage': 0.8
            })
        }
        try:
            config.read(config_file)
        except Exception as e:
            logging.warning(f"Failed to read config file: {e}. Using defaults.")
        return config

    def _setup_logging(self):
        log_level = self.config['DEFAULT'].get('log_level', 'INFO').upper()
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _init_history(self):
        # We run this synchronously during init
        for interface, _ in self._get_network_interfaces_sync().items():
            self.interface_stats[interface] = []

    async def check_connectivity(self, target: str = 'www.google.com', port: int = 80, timeout: float = 3.0) -> ConnectionStatus:
        """Check connectivity asynchronously"""
        try:
            # open_connection does dns resolution and tcp connect asynchronously
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return ConnectionStatus.CONNECTED
        except asyncio.TimeoutError:
            self.logger.warning(f"Connection timeout to {target}:{port}")
            return ConnectionStatus.DEGRADED
        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.logger.error(f"Connection error to {target}:{port} - {str(e)}")
            return ConnectionStatus.DISCONNECTED
        except Exception as e:
            self.logger.error(f"Unexpected connectivity error: {str(e)}")
            return ConnectionStatus.DISCONNECTED

    def _generate_stats(self, io_counters, per_interface: bool) -> Generator[Tuple[str, Dict], None, None]:
        if per_interface:
            for interface, counters in io_counters.items():
                yield interface, asdict(NetworkStats(
                    bytes_sent=counters.bytes_sent, bytes_recv=counters.bytes_recv,
                    packets_sent=counters.packets_sent, packets_recv=counters.packets_recv,
                    errin=counters.errin, errout=counters.errout,
                    dropin=counters.dropin, dropout=counters.dropout
                ))
        else:
            yield 'global', asdict(NetworkStats(
                bytes_sent=io_counters.bytes_sent, bytes_recv=io_counters.bytes_recv,
                packets_sent=io_counters.packets_sent, packets_recv=io_counters.packets_recv,
                errin=io_counters.errin, errout=io_counters.errout,
                dropin=io_counters.dropin, dropout=io_counters.dropout
            ))

    async def get_network_stats(self, per_interface: bool = False) -> Dict:
        """Get comprehensive network statistics asynchronously"""
        stats = {}
        loop = asyncio.get_event_loop()
        io_counters = await loop.run_in_executor(self._executor, lambda: psutil.net_io_counters(pernic=per_interface))
        
        for interface, stat_data in self._generate_stats(io_counters, per_interface):
            if per_interface:
                stats[interface] = stat_data
                self._update_interface_history(interface, stat_data)
            else:
                stats['global'] = stat_data
                self._update_history(stat_data)
                
        self._check_thresholds(stats)
        return stats

    def _update_history(self, stats: Dict):
        if len(self) >= int(self.config['DEFAULT']['history_size']):
            self.history.pop(0)
        self.history.append(NetworkStats(**stats))

    def _update_interface_history(self, interface: str, stats: Dict):
        if interface not in self.interface_stats:
            self.interface_stats[interface] = []
        if len(self.interface_stats[interface]) >= int(self.config['DEFAULT']['history_size']):
            self.interface_stats[interface].pop(0)
        self.interface_stats[interface].append(NetworkStats(**stats))

    def _check_thresholds(self, stats: Dict):
        try:
            thresholds = json.loads(self.config['DEFAULT']['alert_thresholds'])
            for interface, data in stats.items():
                total_packets = data['packets_sent'] + data['packets_recv']
                error_rate = (data['errin'] + data['errout']) / total_packets if total_packets > 0 else 0
                drop_rate = (data['dropin'] + data['dropout']) / total_packets if total_packets > 0 else 0
                
                if error_rate > thresholds['error_rate']:
                    self._add_alert(f"High error rate on {interface}: {error_rate:.2%}", AlertLevel.WARNING, thresholds['error_rate'], error_rate)
                
                if drop_rate > thresholds['drop_rate']:
                    self._add_alert(f"High packet drop rate on {interface}: {drop_rate:.2%}", AlertLevel.WARNING, thresholds['drop_rate'], drop_rate)
        except Exception as e:
            self.logger.error(f"Threshold checking error: {str(e)}")

    def _add_alert(self, message: str, level: AlertLevel, threshold: float = None, value: float = None): # type: ignore
        alert = NetworkAlert(message=message, level=level, threshold=threshold, current_value=value)
        self.alerts.append(alert)
        self.logger.log(getattr(logging, level.name), f"{level.name} - {message}")

    def _get_network_interfaces_sync(self) -> Dict[str, InterfaceInfo]:
        interfaces = {}
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for interface, addresses in addrs.items():
            interface_stat = stats.get(interface)
            interfaces[interface] = InterfaceInfo(
                name=interface,
                is_up=interface_stat.isup if interface_stat else False,
                speed=interface_stat.speed if interface_stat else 0,
                mtu=interface_stat.mtu if interface_stat else 0,
                addresses=[{'family': str(addr.family), 'address': addr.address} for addr in addresses]
            )
        return interfaces

    async def get_network_interfaces(self) -> Dict[str, InterfaceInfo]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get_network_interfaces_sync)

    async def monitor(self, duration: int = 60, interval: int = None): # type: ignore
        if interval is None:
            interval = int(self.config['DEFAULT']['monitor_interval'])
        
        end_time = time.time() + duration
        self.logger.info(f"Starting network monitoring for {duration} seconds...")
        
        try:
            while time.time() < end_time:
                stats = await self.get_network_stats(per_interface=True)
                self.logger.debug(f"Current stats: {stats}")
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            self.logger.info("Monitoring cancelled")
        finally:
            self.logger.info("Monitoring completed")

    async def generate_report(self) -> Dict:
        locald, internet, ifaces, cur_stats = await asyncio.gather(
            self.check_connectivity('127.0.0.1'),
            self.check_connectivity(),
            self.get_network_interfaces(),
            self.get_network_stats(per_interface=True)
        )
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'connectivity': {
                'localhost': locald.name,
                'internet': internet.name
            },
            'interfaces': {k: asdict(v) for k, v in ifaces.items()},
            'current_stats': cur_stats,
            'alerts': [asdict(alert) for alert in self.alerts[-10:]],
            'history_size': len(self)
        }
        return report

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Network Analyzer (Async)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-m", "--monitor", type=int, help="Run in monitoring mode for specified duration (seconds)", metavar="DURATION")
    parser.add_argument("-i", "--interval", type=int, help="Monitoring interval in seconds", default=MONITOR_INTERVAL)
    parser.add_argument("-c", "--config", help="Configuration file path", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-r", "--report", action="store_true", help="Generate and display a network report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

async def async_main():
    args = parse_arguments()
    
    try:
        with NetworkAnalyzer(args.config) as analyzer:
            if args.verbose:
                logging.getLogger().setLevel(logging.DEBUG)
            
            if args.monitor:
                await analyzer.monitor(duration=args.monitor, interval=args.interval)
            elif args.report:
                report = await analyzer.generate_report()
                print(json.dumps(report, indent=2))
            else:
                print("No action specified. Use --help for usage information.")
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except NetworkGatheringError as e:
        print(f"Analyzer Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()) # type: ignore
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
