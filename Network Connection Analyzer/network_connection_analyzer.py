#!/usr/bin/env python3
"""
Industrial-Grade Network Analysis Tool with:
- Comprehensive network monitoring
- Historical data tracking
- Alerting system
- Multi-interface support
- Configurable thresholds
- Enhanced error handling
- Performance optimization
"""

import json
import concurrent
import psutil
import netifaces
import logging
import time
import sys
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor
import configparser
import argparse

# Constants
DEFAULT_CONFIG_FILE = "network_manager.ini"
LOG_FILE = "network_analysis.log"
MAX_WORKERS = 5
HISTORY_SIZE = 1000  # max data points to keep in memory

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
        self._init_history()

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file"""
        config = configparser.ConfigParser()
        
        # Set defaults
        config['DEFAULT'] = {
            'log_level': 'INFO',
            'history_size': str(HISTORY_SIZE),
            'max_workers': str(MAX_WORKERS),
            'alert_thresholds': json.dumps({
                'error_rate': 0.01,  # 1% packet error rate
                'drop_rate': 0.01,    # 1% packet drop rate
                'bandwidth_usage': 0.8  # 80% of interface speed
            })
        }
        
        try:
            config.read(config_file)
        except Exception as e:
            logging.warning(f"Failed to read config file: {e}. Using defaults.")
        
        return config

    def _setup_logging(self):
        """Configure logging system"""
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
        """Initialize history tracking for all interfaces"""
        interfaces = self._get_interface_names()
        for interface in interfaces:
            self.history[interface] = []

    def _get_interface_names(self) -> List[str]:
        """Get list of network interfaces"""
        return list(psutil.net_if_stats().keys())

    def gather_interface_stats(self) -> Dict[str, Dict[str, Any]]:
        """Gather comprehensive interface statistics"""
        stats = {}
        try:
            self.logger.info("Gathering interface statistics...")
            net_stats = psutil.net_if_stats()
            io_counters = psutil.net_io_counters(pernic=True)
            
            for iface, info in net_stats.items():
                stats[iface] = {
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
                self._update_history(iface, stats[iface])
                self._check_thresholds(iface, stats[iface])
            
            self.logger.info("Interface statistics gathered successfully")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error gathering interface stats: {e}")
            raise

    def _update_history(self, interface: str, stats: Dict):
        """Update historical data for an interface"""
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
        """Check stats against configured thresholds"""
        try:
            thresholds = json.loads(self.config['DEFAULT']['alert_thresholds'])
            io = stats['io_counters']
            
            # Calculate rates
            total_packets = io['packets_sent'] + io['packets_recv']
            if total_packets > 0:
                error_rate = (io['errin'] + io['errout']) / total_packets
                drop_rate = (io['dropin'] + io['dropout']) / total_packets
                
                # Check against thresholds
                if error_rate > thresholds['error_rate']:
                    self._add_alert(
                        f"High error rate on {interface}",
                        AlertLevel.WARNING,
                        interface,
                        thresholds['error_rate'],
                        error_rate
                    )
                
                if drop_rate > thresholds['drop_rate']:
                    self._add_alert(
                        f"High packet drop rate on {interface}",
                        AlertLevel.WARNING,
                        interface,
                        thresholds['drop_rate'],
                        drop_rate
                    )
                
                # Check bandwidth usage if speed is known
                if stats['speed'] > 0:
                    elapsed = 1  # Assume 1 second since last check
                    sent_mbps = (io['bytes_sent'] * 8) / (1024 * 1024 * elapsed)
                    recv_mbps = (io['bytes_recv'] * 8) / (1024 * 1024 * elapsed)
                    total_usage = (sent_mbps + recv_mbps) / stats['speed']
                    
                    if total_usage > thresholds['bandwidth_usage']:
                        self._add_alert(
                            f"High bandwidth usage on {interface}",
                            AlertLevel.WARNING,
                            interface,
                            thresholds['bandwidth_usage'],
                            total_usage
                        )
        except Exception as e:
            self.logger.error(f"Threshold checking error: {str(e)}")

    def _add_alert(self, message: str, level: AlertLevel, interface: str, 
                  threshold: float = None, value: float = None):
        """Record a new alert"""
        alert = NetworkAlert(
            message=message,
            level=level,
            interface=interface,
            threshold=threshold,
            current_value=value
        )
        self.alerts.append(alert)
        self.logger.log(
            getattr(logging, level.name),
            f"{level.name} - {interface} - {message}"
        )

    def gather_interface_addresses(self) -> Dict[str, List[Dict[str, str]]]:
        """Gather interface addresses with detailed information"""
        addresses = {}
        try:
            self.logger.info("Gathering interface addresses...")
            addrs = psutil.net_if_addrs()
            
            for iface, addr_list in addrs.items():
                addresses[iface] = []
                for addr in addr_list:
                    addresses[iface].append(asdict(InterfaceAddress(
                        family=self._get_family_name(addr.family),
                        address=addr.address,
                        netmask=addr.netmask,
                        broadcast=addr.broadcast,
                        ptp=addr.ptp
                    )))
            
            self.logger.info("Interface addresses gathered successfully")
            return addresses
            
        except Exception as e:
            self.logger.error(f"Error gathering interface addresses: {e}")
            raise

    def gather_network_connections(self, kinds: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Gather network connections with detailed information"""
        if kinds is None:
            kinds = ['inet', 'inet4', 'inet6', 'tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6']
            
        connections = {}
        try:
            self.logger.info("Gathering network connections...")
            
            with ThreadPoolExecutor(max_workers=int(self.config['DEFAULT']['max_workers'])) as executor:
                futures = {executor.submit(self._gather_connection_kind, kind): kind for kind in kinds}
                for future in concurrent.futures.as_completed(futures):
                    kind = futures[future]
                    try:
                        connections[kind] = future.result()
                    except Exception as e:
                        self.logger.error(f"Error gathering {kind} connections: {e}")
                        connections[kind] = []
            
            self.logger.info("Network connections gathered successfully")
            return connections
            
        except Exception as e:
            self.logger.error(f"Error gathering connections: {e}")
            raise

    def _gather_connection_kind(self, kind: str) -> List[Dict[str, Any]]:
        """Gather connections of a specific kind"""
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
            self.logger.error(f"Error processing {kind} connections: {e}")
            raise
        return conn_list

    def get_gateway_info(self) -> Dict[str, List[GatewayInfo]]:
        """Get detailed gateway information"""
        gateways = {'ipv4': [], 'ipv6': []}
        try:
            self.logger.info("Gathering gateway information...")
            gw_info = netifaces.gateways()
            
            if 'default' in gw_info:
                for family, gateway in gw_info['default'].items():
                    if family == netifaces.AF_INET:
                        gateways['ipv4'].append(asdict(GatewayInfo(
                            ip=gateway[0],
                            interface=gateway[1],
                            metric=gateway[2]
                        )))
                    elif family == netifaces.AF_INET6:
                        gateways['ipv6'].append(asdict(GatewayInfo(
                            ip=gateway[0],
                            interface=gateway[1],
                            metric=gateway[2]
                        )))
            
            self.logger.info("Gateway information gathered successfully")
            return gateways
            
        except Exception as e:
            self.logger.error(f"Error gathering gateway info: {e}")
            raise

    def _get_duplex_name(self, duplex):
        """Safely get the name of the duplex type."""
        try:
            return duplex.name
        except AttributeError:
            return str(duplex)

    def _get_family_name(self, family):
        """Safely get the name of the address family."""
        try:
            return family.name
        except AttributeError:
            return str(family)

    def _get_socket_type_name(self, socket_type):
        """Safely get the name of the socket type."""
        try:
            return socket_type.name
        except AttributeError:
            return str(socket_type)

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive network report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': {
                'stats': self.gather_interface_stats(),
                'addresses': self.gather_interface_addresses()
            },
            'connections': self.gather_network_connections(),
            'gateways': self.get_gateway_info(),
            'alerts': [asdict(alert) for alert in self.alerts[-10:]],  # Last 10 alerts
            'history': {iface: len(stats) for iface, stats in self.history.items()}
        }
        return report

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Network Manager",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-c", "--config",
        help="Configuration file path",
        default=DEFAULT_CONFIG_FILE
    )
    parser.add_argument(
        "-r", "--report",
        action="store_true",
        help="Generate and display a network report"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-m", "--monitor",
        type=int,
        help="Monitor network for specified seconds",
        metavar="SECONDS"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        manager = NetworkManager(args.config)
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        if args.monitor:
            end_time = time.time() + args.monitor
            while time.time() < end_time:
                report = manager.generate_report()
                print(json.dumps(report, indent=2))
                time.sleep(5)  # Update every 5 seconds
        elif args.report:
            report = manager.generate_report()
            print(json.dumps(report, indent=2))
        else:
            print("No action specified. Use --help for usage information.")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
