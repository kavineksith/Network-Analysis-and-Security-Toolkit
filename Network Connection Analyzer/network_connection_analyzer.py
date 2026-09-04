#!/usr/bin/env python3
"""
Industrial-Grade Network Analysis Tool with:
- Asynchronous monitoring to avoid blocking
- ProcessPoolExecutor / ThreadPoolExecutor offloading for synchronous system calls
- Generator-based data processing
- Historical data tracking
- Alerting system
- Dunder methods for pythonic usage
- Custom exception handling
- Configurable thresholds
- Enhanced performance optimization
"""

import json
import psutil
import netifaces
import logging
import time
import sys
import asyncio
from typing import Dict, List, Optional, Tuple, Any, AsyncGenerator, Generator
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum, auto
import configparser
import argparse
from concurrent.futures import ThreadPoolExecutor

# Constants
DEFAULT_CONFIG_FILE = "network_manager.ini"
LOG_FILE = "network_analysis.log"
MAX_WORKERS = 5
HISTORY_SIZE = 1000

class AnalyzerError(Exception):
    """Base exception for Network Analyzer"""
    pass

class InterfaceNotFoundError(AnalyzerError):
    """Exception raised when a specified interface is not found"""
    pass

class InterfaceStatus(Enum):
    UP = auto()
    DOWN = auto()
    DEGRADED = auto()

class AlertLevel(Enum):
    INFO = auto()
    WARNING = auto()
    CRITICAL = auto()

@dataclass
class InterfaceStats:
    is_up: bool
    duplex: str
    speed: int
    mtu: int
    flags: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class InterfaceAddress:
    family: str
    address: str
    netmask: str
    broadcast: str
    ptp: str

@dataclass
class NetworkConnection:
    fd: int
    family: str
    type: str
    local_address: str
    remote_address: str
    status: str
    pid: int

@dataclass
class NetworkAlert:
    message: str
    level: AlertLevel
    interface: str
    threshold: Optional[float] = None
    current_value: Optional[float] = None
    timestamp: float = field(default_factory=time.time)

@dataclass
class GatewayInfo:
    ip: str
    interface: str
    metric: int

class NetworkManager:
    def __init__(self, config_file: str = DEFAULT_CONFIG_FILE):
        self.config = self._load_config(config_file)
        self._setup_logging()
        self.history: Dict[str, List[InterfaceStats]] = {}
        self.alerts: List[NetworkAlert] = []
        self._executor = ThreadPoolExecutor(max_workers=int(self.config['DEFAULT']['max_workers']))
        self._init_history()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit, clean up executor"""
        self._executor.shutdown(wait=False)

    def __getitem__(self, interface: str) -> List[InterfaceStats]:
        """Access history for a specific interface using manager['eth0']"""
        if interface not in self.history:
            raise InterfaceNotFoundError(f"Interface {interface} not found in history.")
        return self.history[interface]

    def __len__(self) -> int:
        """Return the total number of alerts recorded"""
        return len(self.alerts)

    def __iter__(self):
        """Iterate over the active interfaces"""
        return iter(self.history.keys())

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'log_level': 'INFO',
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
        interfaces = self._get_interface_names()
        for interface in interfaces:
            self.history[interface] = []

    def _get_interface_names(self) -> List[str]:
        return list(psutil.net_if_stats().keys())

    def _generate_interface_stats(self, net_stats, io_counters) -> Generator[Tuple[str, Dict], None, None]:
        """Generator to yield interface stats"""
        for iface, info in net_stats.items():
            yield iface, {
                'status': InterfaceStatus.UP if info.isup else InterfaceStatus.DOWN,
                'duplex': self._get_duplex_name(info.duplex),
                'speed': info.speed,
                'mtu': info.mtu,
                'flags': info.flags,
                'io_counters': {
                    'bytes_sent': io_counters[iface].bytes_sent,
                    'bytes_recv': io_counters[iface].bytes_recv,
                    'packets_sent': io_counters[iface].packets_sent,
                    'packets_recv': io_counters[iface].packets_recv,
                    'errin': io_counters[iface].errin,
                    'errout': io_counters[iface].errout,
                    'dropin': io_counters[iface].dropin,
                    'dropout': io_counters[iface].dropout
                }
            }

    async def gather_interface_stats(self) -> Dict[str, Dict[str, Any]]:
        """Gather comprehensive interface statistics asynchronously"""
        stats = {}
        try:
            self.logger.info("Gathering interface statistics...")
            loop = asyncio.get_event_loop()
            
            # Offload synchronous system calls to executor
            net_stats = await loop.run_in_executor(self._executor, psutil.net_if_stats)
            io_counters = await loop.run_in_executor(self._executor, lambda: psutil.net_io_counters(pernic=True))
            
            for iface, stat_data in self._generate_interface_stats(net_stats, io_counters):
                stats[iface] = stat_data
                self._update_history(iface, stat_data)
                self._check_thresholds(iface, stat_data)
            
            self.logger.info("Interface statistics gathered successfully")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error gathering interface stats: {e}")
            raise AnalyzerError(f"Failed to gather interface stats: {e}")

    def _update_history(self, interface: str, stats: Dict):
        if interface not in self.history:
            self.history[interface] = []
            
        if len(self.history[interface]) >= int(self.config['DEFAULT']['history_size']):
            self.history[interface].pop(0)
            
        self.history[interface].append(InterfaceStats(
            is_up=stats['status'] == InterfaceStatus.UP,
            duplex=stats['duplex'],
            speed=stats['speed'],
            mtu=stats['mtu'],
            flags=stats['flags']
        ))

    def _check_thresholds(self, interface: str, stats: Dict):
        try:
            thresholds = json.loads(self.config['DEFAULT']['alert_thresholds'])
            io = stats['io_counters']
            
            total_packets = io['packets_sent'] + io['packets_recv']
            if total_packets > 0:
                error_rate = (io['errin'] + io['errout']) / total_packets
                drop_rate = (io['dropin'] + io['dropout']) / total_packets
                
                if error_rate > thresholds['error_rate']:
                    self._add_alert(f"High error rate on {interface}", AlertLevel.WARNING, interface, thresholds['error_rate'], error_rate)
                
                if drop_rate > thresholds['drop_rate']:
                    self._add_alert(f"High packet drop rate on {interface}", AlertLevel.WARNING, interface, thresholds['drop_rate'], drop_rate)
                
                if stats['speed'] > 0:
                    elapsed = 1
                    sent_mbps = (io['bytes_sent'] * 8) / (1024 * 1024 * elapsed)
                    recv_mbps = (io['bytes_recv'] * 8) / (1024 * 1024 * elapsed)
                    total_usage = (sent_mbps + recv_mbps) / stats['speed']
                    
                    if total_usage > thresholds['bandwidth_usage']:
                        self._add_alert(f"High bandwidth usage on {interface}", AlertLevel.WARNING, interface, thresholds['bandwidth_usage'], total_usage)
        except Exception as e:
            self.logger.error(f"Threshold checking error: {str(e)}")

    def _add_alert(self, message: str, level: AlertLevel, interface: str, threshold: float = None, value: float = None):
        alert = NetworkAlert(message, level, interface, threshold, value)
        self.alerts.append(alert)
        self.logger.log(getattr(logging, level.name), f"{level.name} - {interface} - {message}")

    def _generate_addresses(self, addrs) -> Generator[Tuple[str, List[Dict[str, str]]], None, None]:
        for iface, addr_list in addrs.items():
            yield iface, [asdict(InterfaceAddress(
                family=self._get_family_name(addr.family),
                address=addr.address,
                netmask=addr.netmask,
                broadcast=addr.broadcast,
                ptp=addr.ptp
            )) for addr in addr_list]

    async def gather_interface_addresses(self) -> Dict[str, List[Dict[str, str]]]:
        addresses = {}
        try:
            self.logger.info("Gathering interface addresses...")
            loop = asyncio.get_event_loop()
            addrs = await loop.run_in_executor(self._executor, psutil.net_if_addrs)
            
            for iface, addr_data in self._generate_addresses(addrs):
                addresses[iface] = addr_data
            
            self.logger.info("Interface addresses gathered successfully")
            return addresses
        except Exception as e:
            self.logger.error(f"Error gathering interface addresses: {e}")
            raise AnalyzerError(f"Failed to gather interface addresses: {e}")

    async def gather_network_connections(self, kinds: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        if kinds is None:
            kinds = ['inet', 'inet4', 'inet6', 'tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6']
            
        connections = {}
        try:
            self.logger.info("Gathering network connections...")
            
            # Run in parallel using asyncio.gather
            tasks = [self._gather_connection_kind_async(kind) for kind in kinds]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for kind, result in zip(kinds, results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error gathering {kind} connections: {result}")
                    connections[kind] = []
                else:
                    connections[kind] = result
            
            self.logger.info("Network connections gathered successfully")
            return connections
        except Exception as e:
            self.logger.error(f"Error gathering connections: {e}")
            raise AnalyzerError(f"Failed to gather connections: {e}")

    async def _gather_connection_kind_async(self, kind: str) -> List[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._gather_connection_kind, kind)

    def _gather_connection_kind(self, kind: str) -> List[Dict[str, Any]]:
        """Synchronous part of connection gathering"""
        conn_list = []
        try:
            for conn in psutil.net_connections(kind=kind):
                conn_list.append(asdict(NetworkConnection(
                    fd=conn.fd,
                    family=self._get_family_name(conn.family),
                    type=self._get_socket_type_name(conn.type),
                    local_address=f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    remote_address=f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    status=conn.status,
                    pid=conn.pid if conn.pid is not None else -1
                )))
        except Exception as e:
            logging.error(f"Error processing {kind} connections: {e}")
            raise
        return conn_list

    async def get_gateway_info(self) -> Dict[str, List[GatewayInfo]]:
        gateways = {'ipv4': [], 'ipv6': []}
        try:
            self.logger.info("Gathering gateway information...")
            loop = asyncio.get_event_loop()
            gw_info = await loop.run_in_executor(self._executor, netifaces.gateways)
            
            if 'default' in gw_info:
                for family, gateway in gw_info['default'].items():
                    if family == netifaces.AF_INET:
                        gateways['ipv4'].append(asdict(GatewayInfo(ip=gateway[0], interface=gateway[1], metric=gateway[2])))
                    elif family == netifaces.AF_INET6:
                        gateways['ipv6'].append(asdict(GatewayInfo(ip=gateway[0], interface=gateway[1], metric=gateway[2])))
            
            self.logger.info("Gateway information gathered successfully")
            return gateways
        except Exception as e:
            self.logger.error(f"Error gathering gateway info: {e}")
            raise AnalyzerError(f"Failed to gather gateway info: {e}")

    def _get_duplex_name(self, duplex):
        try:
            return duplex.name
        except AttributeError:
            return str(duplex)

    def _get_family_name(self, family):
        try:
            return family.name
        except AttributeError:
            return str(family)

    def _get_socket_type_name(self, socket_type):
        try:
            return socket_type.name
        except AttributeError:
            return str(socket_type)

    async def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive network report asynchronously"""
        stats_task = self.gather_interface_stats()
        addrs_task = self.gather_interface_addresses()
        conn_task = self.gather_network_connections()
        gw_task = self.get_gateway_info()
        
        stats, addrs, connections, gateways = await asyncio.gather(stats_task, addrs_task, conn_task, gw_task)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': {
                'stats': stats,
                'addresses': addrs
            },
            'connections': connections,
            'gateways': gateways,
            'alerts': [asdict(alert) for alert in self.alerts[-10:]],
            'history': {iface: len(stats) for iface, stats in self.history.items()}
        }
        return report

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Network Manager (Async)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--config", help="Configuration file path", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-r", "--report", action="store_true", help="Generate and display a network report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-m", "--monitor", type=int, help="Monitor network for specified seconds", metavar="SECONDS")
    return parser.parse_args()

async def async_main():
    args = parse_arguments()
    
    try:
        with NetworkManager(args.config) as manager:
            if args.verbose:
                logging.getLogger().setLevel(logging.DEBUG)
            
            if args.monitor:
                end_time = time.time() + args.monitor
                while time.time() < end_time:
                    report = await manager.generate_report()
                    print(json.dumps(report, indent=2))
                    await asyncio.sleep(5)  # Non-blocking sleep
            elif args.report:
                report = await manager.generate_report()
                print(json.dumps(report, indent=2))
            else:
                print("No action specified. Use --help for usage information.")
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except AnalyzerError as e:
        print(f"Analysis Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
