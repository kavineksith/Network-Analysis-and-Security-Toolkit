#!/usr/bin/env python3
"""
Industrial-Grade Port Scanner with enhanced features:
- Multithreading for faster scans
- Comprehensive error handling
- Configurable timeouts and retries
- Service fingerprinting
- IP range scanning
- Rate limiting
- Detailed logging
- Output in multiple formats (CSV, JSON)
- Configuration file support
- Progress tracking
"""

import socket
import struct
import sys
import csv
import json
import time
import threading
import ipaddress
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import configparser

# Constants
DEFAULT_TIMEOUT = 1.0  # seconds
DEFAULT_THREADS = 50
MAX_RETRIES = 2
MAX_BANNER_LENGTH = 1024
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_CONFIG_FILE = 'port_scanner.ini'

@dataclass
class ScanResult:
    port: int
    protocol: str
    service: str
    status: str
    ip_address: str
    banner: str
    response_time: float

class PortScanner:
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.results: List[ScanResult] = []
        self.lock = threading.Lock()
        self.scan_stats = {
            'total_ports': 0,
            'scanned_ports': 0,
            'open_ports': 0,
            'start_time': 0,
            'end_time': 0
        }
        self._setup_logging()
        
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file or use defaults"""
        config = configparser.ConfigParser()
        
        # Set defaults
        config['DEFAULT'] = {
            'timeout': str(DEFAULT_TIMEOUT),
            'max_threads': str(DEFAULT_THREADS),
            'max_retries': str(MAX_RETRIES),
            'banner_grab': 'True',
            'rate_limit': '0',  # 0 means no limit
            'log_level': 'INFO',
            'output_format': 'csv'
        }
        
        if config_file:
            try:
                config.read(config_file)
            except Exception as e:
                logging.warning(f"Failed to read config file: {e}. Using defaults.")
        
        return config

    def _setup_logging(self):
        """Configure logging based on settings"""
        log_level = self.config['DEFAULT'].get('log_level', 'INFO').upper()
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format=LOG_FORMAT,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('port_scanner.log')
            ]
        )

    def scan_targets(self, targets: List[str], ports: List[int], protocols: List[str] = ['tcp', 'udp']) -> List[ScanResult]:
        """Scan multiple targets with specified ports and protocols"""
        self.scan_stats['start_time'] = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=int(self.config['DEFAULT']['max_threads'])) as executor:
                futures = []
                
                for target in targets:
                    for port in ports:
                        for protocol in protocols:
                            futures.append(
                                executor.submit(
                                    self._scan_port,
                                    target, port, protocol
                                )
                            )
                
                self.scan_stats['total_ports'] = len(futures)
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result and result.status.lower() == 'open':
                            with self.lock:
                                self.results.append(result)
                                self.scan_stats['open_ports'] += 1
                    except Exception as e:
                        logging.error(f"Error processing scan result: {e}")
                    finally:
                        with self.lock:
                            self.scan_stats['scanned_ports'] += 1
                
        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            raise
        
        self.scan_stats['end_time'] = time.time()
        return self.results

    def _scan_port(self, target: str, port: int, protocol: str) -> Optional[ScanResult]:
        """Scan a single port with retries and rate limiting"""
        rate_limit = float(self.config['DEFAULT']['rate_limit'])
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
        
        retries = int(self.config['DEFAULT']['max_retries'])
        timeout = float(self.config['DEFAULT']['timeout'])
        
        for attempt in range(retries + 1):
            try:
                start_time = time.time()
                
                if protocol.lower() == 'tcp':
                    status, banner = self._scan_tcp_port(target, port, timeout)
                elif protocol.lower() == 'udp':
                    status, banner = self._scan_udp_port(target, port, timeout)
                elif protocol.lower() == 'icmp':
                    return self._scan_icmp(target)
                else:
                    logging.warning(f"Unsupported protocol: {protocol}")
                    return None
                
                response_time = time.time() - start_time
                service = self._get_service_name(port, protocol)
                
                return ScanResult(
                    port=port,
                    protocol=protocol,
                    service=service,
                    status=status,
                    ip_address=target,
                    banner=banner,
                    response_time=response_time
                )
                
            except socket.timeout:
                if attempt == retries:
                    return ScanResult(
                        port=port,
                        protocol=protocol,
                        service="Unknown",
                        status="Closed",
                        ip_address=target,
                        banner="Timeout",
                        response_time=0
                    )
            except socket.error as e:
                logging.debug(f"Socket error scanning {target}:{port}/{protocol}: {e}")
                if attempt == retries:
                    return ScanResult(
                        port=port,
                        protocol=protocol,
                        service="Unknown",
                        status="Error",
                        ip_address=target,
                        banner=str(e),
                        response_time=0
                    )
            except Exception as e:
                logging.error(f"Unexpected error scanning {target}:{port}/{protocol}: {e}")
                if attempt == retries:
                    return ScanResult(
                        port=port,
                        protocol=protocol,
                        service="Unknown",
                        status="Error",
                        ip_address=target,
                        banner=str(e),
                        response_time=0
                    )
            
            time.sleep(0.1 * (attempt + 1))  # Backoff between retries
        
        return None

    def _scan_tcp_port(self, target: str, port: int, timeout: float) -> Tuple[str, str]:
        """Scan a TCP port and attempt to grab banner if open"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            
            if result == 0:
                banner = "Unknown"
                if self.config['DEFAULT'].getboolean('banner_grab'):
                    try:
                        banner = s.recv(MAX_BANNER_LENGTH)
                        banner = self._clean_banner(banner)
                    except (socket.timeout, socket.error):
                        pass
                return "Open", banner
            return "Closed", "Unknown"

    def _scan_udp_port(self, target: str, port: int, timeout: float) -> Tuple[str, str]:
        """Scan a UDP port"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            
            try:
                # Send empty UDP packet
                s.sendto(b'', (target, port))
                
                try:
                    # Some UDP services might respond
                    data, _ = s.recvfrom(MAX_BANNER_LENGTH)
                    return "Open", self._clean_banner(data)
                except socket.timeout:
                    # No response could mean filtered or open but not responding
                    return "Open|Filtered", "Unknown"
                    
            except socket.error:
                return "Error", "Unknown"

    def _scan_icmp(self, target: str) -> ScanResult:
        """Perform ICMP ping to check host availability"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(float(self.config['DEFAULT']['timeout']))
                
                packet_id = int(time.time()) % 65535
                sequence = 1
                icmp_request = self._create_icmp_request(packet_id, sequence)
                
                start_time = time.time()
                s.sendto(icmp_request, (target, 0))
                
                try:
                    response, _ = s.recvfrom(1024)
                    response_time = time.time() - start_time
                    if self._is_icmp_response_valid(response, packet_id):
                        return ScanResult(
                            port=0,
                            protocol="icmp",
                            service="icmp-echo",
                            status="Open",
                            ip_address=target,
                            banner=f"Response time: {response_time:.2f}s",
                            response_time=response_time
                        )
                except socket.timeout:
                    pass
                
                return ScanResult(
                    port=0,
                    protocol="icmp",
                    service="icmp-echo",
                    status="Closed",
                    ip_address=target,
                    banner="No response",
                    response_time=0
                )
                
        except PermissionError:
            logging.warning("ICMP requires root privileges on Unix systems")
            return ScanResult(
                port=0,
                protocol="icmp",
                service="icmp-echo",
                status="Error",
                ip_address=target,
                banner="Permission denied",
                response_time=0
            )
        except Exception as e:
            logging.error(f"ICMP scan error: {e}")
            return ScanResult(
                port=0,
                protocol="icmp",
                service="icmp-echo",
                status="Error",
                ip_address=target,
                banner=str(e),
                response_time=0
            )

    def _clean_banner(self, banner: bytes) -> str:
        """Clean and decode banner data"""
        try:
            if not banner:
                return "Unknown"
            
            decoded = banner.decode(errors='ignore').strip()
            return ' '.join(decoded.splitlines())[:500]  # Limit length and remove newlines
        except Exception:
            return "Unknown"

    def _get_service_name(self, port: int, protocol: str) -> str:
        """Get service name for port/protocol"""
        try:
            return socket.getservbyport(port, protocol)
        except (OSError, socket.error):
            # Check common services not in /etc/services
            common_services = {
                (80, 'tcp'): 'http',
                (443, 'tcp'): 'https',
                (3306, 'tcp'): 'mysql',
                (5432, 'tcp'): 'postgresql',
                (27017, 'tcp'): 'mongodb',
                (6379, 'tcp'): 'redis',
                (53, 'udp'): 'dns',
                (161, 'udp'): 'snmp'
            }
            return common_services.get((port, protocol), "Unknown")

    def _create_icmp_request(self, packet_id: int, sequence: int) -> bytes:
        """Create ICMP Echo Request packet"""
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_identifier = packet_id
        icmp_seq_number = sequence
        
        # Header without checksum
        header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number)
        
        # Calculate checksum
        checksum = self._calculate_checksum(header)
        
        # Final header with checksum
        return struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_identifier, icmp_seq_number)

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'  # Pad to even length
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return ~checksum & 0xFFFF

    def _is_icmp_response_valid(self, response: bytes, packet_id: int) -> bool:
        """Validate ICMP Echo Reply"""
        if len(response) < 28:  # Minimum ICMP response size
            return False
            
        icmp_type = response[20]
        icmp_code = response[21]
        
        if icmp_type == 0 and icmp_code == 0:  # Echo Reply
            received_id = (response[24] << 8) + response[25]
            return received_id == packet_id
        
        return False

    def print_results(self):
        """Print scan results in a formatted table"""
        if not self.results:
            print("No open ports found.")
            return
            
        print("\nScan Results:")
        print("{:<8} {:<8} {:<20} {:<10} {:<15} {:<50}".format(
            "Port", "Proto", "Service", "Status", "Response Time", "Banner"))
        print("-" * 120)
        
        for result in sorted(self.results, key=lambda x: (x.ip_address, x.port, x.protocol)):
            print("{:<8} {:<8} {:<20} {:<10} {:<15.2f} {:<50}".format(
                result.port,
                result.protocol.upper(),
                result.service,
                result.status,
                result.response_time,
                result.banner[:47] + '...' if len(result.banner) > 50 else result.banner
            ))
        
        self._print_stats()

    def _print_stats(self):
        """Print scan statistics"""
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        ports_per_sec = self.scan_stats['scanned_ports'] / duration if duration > 0 else 0
        
        print("\nScan Statistics:")
        print(f"- Targets scanned: {len({r.ip_address for r in self.results})}")
        print(f"- Ports scanned: {self.scan_stats['scanned_ports']}/{self.scan_stats['total_ports']}")
        print(f"- Open ports found: {self.scan_stats['open_ports']}")
        print(f"- Scan duration: {duration:.2f} seconds")
        print(f"- Scan speed: {ports_per_sec:.1f} ports/second")

    def save_results(self, filename: str, format: str = None):
        """Save results to file in specified format"""
        if not format:
            format = self.config['DEFAULT'].get('output_format', 'csv').lower()
        
        try:
            if format == 'csv':
                self._save_to_csv(filename)
            elif format == 'json':
                self._save_to_json(filename)
            else:
                logging.error(f"Unsupported output format: {format}")
                return
                
            logging.info(f"Results saved to {filename} ({format.upper()})")
        except Exception as e:
            logging.error(f"Failed to save results: {e}")

    def _save_to_csv(self, filename: str):
        """Save results to CSV file"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'Service', 'Status', 'IP Address', 'Banner', 'Response Time'])
            for result in self.results:
                writer.writerow([
                    result.port,
                    result.protocol,
                    result.service,
                    result.status,
                    result.ip_address,
                    result.banner,
                    f"{result.response_time:.4f}"
                ])

    def _save_to_json(self, filename: str):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump({
                'results': [asdict(r) for r in self.results],
                'stats': self.scan_stats
            }, f, indent=2)

def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification string into list of ports"""
    ports = set()
    
    for part in port_spec.split(','):
        part = part.strip()
        if not part:
            continue
            
        if '-' in part:
            start, end = part.split('-', 1)
            try:
                start_port = int(start)
                end_port = int(end)
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    ports.update(range(start_port, end_port + 1))
                else:
                    raise ValueError(f"Invalid port range: {part}")
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    raise ValueError(f"Invalid port number: {port}")
            except ValueError:
                service = part.lower()
                try:
                    port = socket.getservbyname(service)
                    ports.add(port)
                except socket.error:
                    raise ValueError(f"Unknown service: {service}")
    
    return sorted(ports)

def parse_targets(target_spec: str) -> List[str]:
    """Parse target specification into list of IP addresses"""
    targets = set()
    
    for part in target_spec.split(','):
        part = part.strip()
        if not part:
            continue
            
        if '/' in part:
            # CIDR notation
            try:
                network = ipaddress.ip_network(part, strict=False)
                for host in network.hosts():
                    targets.add(str(host))
            except ValueError as e:
                raise ValueError(f"Invalid network specification '{part}': {e}")
        elif '-' in part:
            # IP range (e.g., 192.168.1.1-100)
            base, range_part = part.rsplit('.', 1)
            if '-' in range_part:
                start, end = range_part.split('-', 1)
                try:
                    start_ip = int(start)
                    end_ip = int(end)
                    if 0 <= start_ip <= 255 and 0 <= end_ip <= 255 and start_ip <= end_ip:
                        for i in range(start_ip, end_ip + 1):
                            targets.add(f"{base}.{i}")
                    else:
                        raise ValueError(f"Invalid IP range: {part}")
                except ValueError:
                    raise ValueError(f"Invalid IP range: {part}")
            else:
                targets.add(part)
        else:
            # Single IP or hostname
            try:
                # Check if it's an IP address
                ipaddress.ip_address(part)
                targets.add(part)
            except ValueError:
                # Try to resolve hostname
                try:
                    ip = socket.gethostbyname(part)
                    targets.add(ip)
                except socket.gaierror:
                    raise ValueError(f"Could not resolve hostname: {part}")
    
    return sorted(targets)

def main():
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Port Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        'targets',
        help="Target IP(s), hostname(s), CIDR notation, or IP ranges (e.g., 192.168.1.1,example.com,10.0.0.0/24,192.168.1.1-100)"
    )
    parser.add_argument(
        'ports',
        help="Port(s) to scan (e.g., 80,443,8000-9000,http,https)"
    )
    parser.add_argument(
        '-o', '--output',
        help="Output file name",
        default="scan_results"
    )
    parser.add_argument(
        '-f', '--format',
        choices=['csv', 'json'],
        help="Output format",
        default=None
    )
    parser.add_argument(
        '-p', '--protocols',
        help="Protocols to scan (comma-separated: tcp,udp,icmp)",
        default="tcp,udp"
    )
    parser.add_argument(
        '-c', '--config',
        help="Configuration file",
        default=DEFAULT_CONFIG_FILE
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    try:
        # Parse inputs
        targets = parse_targets(args.targets)
        ports = parse_ports(args.ports)
        protocols = [p.strip().lower() for p in args.protocols.split(',') if p.strip()]
        
        # Validate protocols
        valid_protocols = {'tcp', 'udp', 'icmp'}
        for protocol in protocols:
            if protocol not in valid_protocols:
                raise ValueError(f"Invalid protocol: {protocol}. Valid options are: {', '.join(valid_protocols)}")
        
        # Initialize scanner
        scanner = PortScanner(args.config)
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        logging.info(f"Starting scan of {len(targets)} target(s), {len(ports)} port(s), protocols: {', '.join(protocols)}")
        
        # Perform scan
        results = scanner.scan_targets(targets, ports, protocols)
        
        # Output results
        if results:
            scanner.print_results()
            output_file = f"{args.output}.{args.format or scanner.config['DEFAULT'].get('output_format', 'csv')}"
            scanner.save_results(output_file, args.format)
        else:
            logging.info("No open ports found.")
            
    except ValueError as e:
        logging.error(f"Input error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
