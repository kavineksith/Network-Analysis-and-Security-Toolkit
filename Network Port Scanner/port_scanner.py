#!/usr/bin/env python3
"""
Industrial-Grade Port Scanner with enhanced features:
- Asynchronous I/O for maximum performance
- Comprehensive error handling with custom exceptions
- Configurable timeouts and retries
- Service fingerprinting
- Generator-based target parsing for memory optimization
- Rate limiting
- Detailed logging
- Output in multiple formats (CSV, JSON)
- Configuration file support
- Dunder methods for pythonic usage
"""

import socket
import struct
import sys
import csv
import json
import time
import asyncio
import ipaddress
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Union, AsyncGenerator, Any
from concurrent.futures import ProcessPoolExecutor
import argparse
import configparser

# Constants
DEFAULT_TIMEOUT = 1.0  # seconds
DEFAULT_CONCURRENCY = 1000
MAX_RETRIES = 2
MAX_BANNER_LENGTH = 1024
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_CONFIG_FILE = 'port_scanner.ini'

# Custom Exceptions
class NetworkScannerError(Exception):
    """Base exception for Network Scanner"""
    pass

class ConfigurationError(NetworkScannerError):
    """Raised when there is an issue with configuration"""
    pass

class TargetResolutionError(NetworkScannerError):
    """Raised when a target cannot be resolved"""
    pass

@dataclass
class ScanResult:
    port: int
    protocol: str
    service: str
    status: str
    ip_address: str
    banner: str
    response_time: float

    def __bool__(self) -> bool:
        return self.status.lower() == 'open'

    def __str__(self) -> str:
        banner_display = self.banner[:47] + '...' if len(self.banner) > 50 else self.banner
        return f"{self.port:<8} {self.protocol.upper():<8} {self.service:<20} {self.status:<10} {self.response_time:<15.2f} {banner_display:<50}"

    def __repr__(self) -> str:
        return f"<ScanResult {self.ip_address}:{self.port}/{self.protocol} - {self.status}>"

class PortScanner:
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.results: List[ScanResult] = []
        self.scan_stats = {
            'total_ports': 0,
            'scanned_ports': 0,
            'open_ports': 0,
            'start_time': 0.0,
            'end_time': 0.0
        }
        self._setup_logging()
        self._semaphore = asyncio.Semaphore(int(self.config['DEFAULT'].get('max_concurrency', DEFAULT_CONCURRENCY)))

    def __enter__(self):
        self.scan_stats['start_time'] = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.scan_stats['end_time'] = time.time()

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file or use defaults"""
        config = configparser.ConfigParser()
        
        # Set defaults
        config['DEFAULT'] = {
            'timeout': str(DEFAULT_TIMEOUT),
            'max_concurrency': str(DEFAULT_CONCURRENCY),
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

    async def scan_targets(self, targets_gen, ports_gen, protocols: List[str] = None):
        """Scan multiple targets with specified ports and protocols using asyncio"""
        if protocols is None:
            protocols = ['tcp', 'udp']
        
        self.scan_stats['start_time'] = time.time()
        
        targets = list(targets_gen)
        ports = list(ports_gen)
        
        self.scan_stats['total_ports'] = len(targets) * len(ports) * len(protocols)
        
        tasks = []
        for target in targets:
            for port in ports:
                for protocol in protocols:
                    tasks.append(self._scan_port_with_semaphore(target, port, protocol))
                    
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in completed:
            if isinstance(result, Exception):
                logging.error(f"Error processing scan result: {result}")
            elif result:
                self.results.append(result)
                if bool(result):
                    self.scan_stats['open_ports'] += 1
            self.scan_stats['scanned_ports'] += 1
            
        self.scan_stats['end_time'] = time.time()
        return self.results

    async def _scan_port_with_semaphore(self, target: str, port: int, protocol: str) -> Optional[ScanResult]:
        async with self._semaphore:
            rate_limit = float(self.config['DEFAULT']['rate_limit'])
            if rate_limit > 0:
                await asyncio.sleep(1.0 / rate_limit)
            return await self._scan_port(target, port, protocol)

    async def _scan_port(self, target: str, port: int, protocol: str) -> Optional[ScanResult]:
        """Scan a single port with retries"""
        retries = int(self.config['DEFAULT']['max_retries'])
        timeout = float(self.config['DEFAULT']['timeout'])
        
        for attempt in range(retries + 1):
            try:
                start_time = time.time()
                
                if protocol.lower() == 'tcp':
                    status, banner = await self._scan_tcp_port(target, port, timeout)
                elif protocol.lower() == 'udp':
                    status, banner = await self._scan_udp_port(target, port, timeout)
                elif protocol.lower() == 'icmp':
                    return await self._scan_icmp(target)
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
                
            except asyncio.TimeoutError:
                if attempt == retries:
                    return ScanResult(port, protocol, "Unknown", "Closed", target, "Timeout", 0)
            except (ConnectionRefusedError, OSError) as e:
                if attempt == retries:
                    status = "Closed" if isinstance(e, ConnectionRefusedError) else "Error"
                    return ScanResult(port, protocol, "Unknown", status, target, str(e), 0)
            except Exception as e:
                logging.error(f"Unexpected error scanning {target}:{port}/{protocol}: {e}")
                if attempt == retries:
                    return ScanResult(port, protocol, "Unknown", "Error", target, str(e), 0)
            
            await asyncio.sleep(0.1 * (attempt + 1))  # Backoff between retries
        
        return None

    async def _scan_tcp_port(self, target: str, port: int, timeout: float) -> Tuple[str, str]:
        """Scan a TCP port asynchronously and attempt to grab banner if open"""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
            banner = "Unknown"
            if self.config['DEFAULT'].getboolean('banner_grab'):
                try:
                    data = await asyncio.wait_for(reader.read(MAX_BANNER_LENGTH), timeout=timeout)
                    banner = self._clean_banner(data)
                except (asyncio.TimeoutError, ConnectionResetError, OSError):
                    pass
            writer.close()
            await writer.wait_closed()
            return "Open", banner
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return "Closed", "Unknown"

    async def _scan_udp_port(self, target: str, port: int, timeout: float) -> Tuple[str, str]:
        """Scan a UDP port - this is inherently unreliable as UDP is connectionless."""
        class UDPProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.transport = None
                self.response_future = asyncio.Future()
            def connection_made(self, transport):
                self.transport = transport
                self.transport.sendto(b'\x00')
            def datagram_received(self, data, addr):
                if not self.response_future.done():
                    self.response_future.set_result(data)
            def error_received(self, exc):
                if not self.response_future.done():
                    self.response_future.set_exception(exc)

        loop = asyncio.get_event_loop()
        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(lambda: UDPProtocol(), remote_addr=(target, port)),
                timeout=timeout
            )
            try:
                data = await asyncio.wait_for(protocol.response_future, timeout=timeout)
                transport.close()
                return "Open", self._clean_banner(data)
            except asyncio.TimeoutError:
                transport.close()
                return "Open|Filtered", "Unknown"
        except Exception:
            return "Closed", "Unknown"

    async def _scan_icmp(self, target: str) -> ScanResult:
        """Perform ICMP ping to check host availability. Done asynchronously via subprocess."""
        param = '-n' if sys.platform.lower() == 'win32' else '-c'
        command = f"ping {param} 1 {target}"
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.config['DEFAULT'].getfloat('timeout'))
            response_time = time.time() - start_time
            
            if process.returncode == 0:
                return ScanResult(0, "icmp", "icmp-echo", "Open", target, f"Response time: {response_time:.2f}s", response_time)
            else:
                return ScanResult(0, "icmp", "icmp-echo", "Closed", target, "No response", 0)
        except asyncio.TimeoutError:
             return ScanResult(0, "icmp", "icmp-echo", "Closed", target, "Timeout", 0)
        except Exception as e:
             return ScanResult(0, "icmp", "icmp-echo", "Error", target, str(e), 0)

    def _clean_banner(self, banner: bytes) -> str:
        """Clean and decode banner data"""
        try:
            if not banner:
                return "Unknown"
            
            decoded = banner.decode(errors='ignore').strip()
            return ' '.join(decoded.splitlines())[:500]
        except Exception:
            return "Unknown"

    def _get_service_name(self, port: int, protocol: str) -> str:
        """Get service name for port/protocol"""
        try:
            return socket.getservbyport(port, protocol)
        except (OSError, socket.error):
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
            print(result)
        
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

def generate_ports(port_spec: str):
    """Generator to parse port specification string and yield ports"""
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
                    for p in range(start_port, end_port + 1):
                        yield p
                else:
                    raise ConfigurationError(f"Invalid port range: {part}")
            except ValueError:
                raise ConfigurationError(f"Invalid port range: {part}")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    yield port
                else:
                    raise ConfigurationError(f"Invalid port number: {port}")
            except ValueError:
                service = part.lower()
                try:
                    port = socket.getservbyname(service)
                    yield port
                except socket.error:
                    raise ConfigurationError(f"Unknown service: {service}")

def generate_targets(target_spec: str):
    """Generator to parse target specification and yield IP addresses"""
    for part in target_spec.split(','):
        part = part.strip()
        if not part:
            continue
            
        if '/' in part:
            # CIDR notation
            try:
                network = ipaddress.ip_network(part, strict=False)
                for host in network.hosts():
                    yield str(host)
            except ValueError as e:
                raise ConfigurationError(f"Invalid network specification '{part}': {e}")
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
                            yield f"{base}.{i}"
                    else:
                        raise ConfigurationError(f"Invalid IP range: {part}")
                except ValueError:
                    raise ConfigurationError(f"Invalid IP range: {part}")
            else:
                yield part
        else:
            # Single IP or hostname
            try:
                ipaddress.ip_address(part)
                yield part
            except ValueError:
                try:
                    ip = socket.gethostbyname(part)
                    yield ip
                except socket.gaierror:
                    raise TargetResolutionError(f"Could not resolve hostname: {part}")

async def async_main():
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Port Scanner (Async Optimized)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        'targets',
        help="Target IP(s), hostname(s), CIDR notation, or IP ranges (e.g., 192.168.1.1,example.com,10.0.0.0/24)"
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
        targets_gen = set(generate_targets(args.targets))
        ports_gen = set(generate_ports(args.ports))
        protocols = [p.strip().lower() for p in args.protocols.split(',') if p.strip()]
        
        valid_protocols = {'tcp', 'udp', 'icmp'}
        for protocol in protocols:
            if protocol not in valid_protocols:
                raise ConfigurationError(f"Invalid protocol: {protocol}. Valid options are: {', '.join(valid_protocols)}")
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            
        logging.info(f"Starting scan of target(s), port(s), protocols: {', '.join(protocols)}")
        
        with PortScanner(args.config) as scanner:
            results = await scanner.scan_targets(targets_gen, ports_gen, protocols)
            
            if results:
                scanner.print_results()
                output_file = f"{args.output}.{args.format or scanner.config['DEFAULT'].get('output_format', 'csv')}"
                scanner.save_results(output_file, args.format)
            else:
                logging.info("No open ports found.")
                
    except NetworkScannerError as e:
        logging.error(f"Scanner error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
