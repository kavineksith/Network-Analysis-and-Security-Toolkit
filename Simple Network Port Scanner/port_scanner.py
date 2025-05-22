#!/usr/bin/env python3
"""
Industrial-Grade Port Scanner with:
- Multithreading for faster scans
- Comprehensive error handling
- Configurable timeouts
- Multiple scan techniques
- Banner grabbing
- Detailed reporting
"""

import socket
import sys
import threading
import concurrent.futures
import time
import argparse
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class PortResult:
    port: int
    is_open: bool
    banner: Optional[str] = None
    response_time: Optional[float] = None

class PortScanner:
    def __init__(self, ip_address: str, start_port: int, end_port: int, 
                 timeout: float = 1.0, max_threads: int = 100, 
                 banner_grab: bool = True):
        self.ip_address = ip_address
        self.start_port = int(start_port)
        self.end_port = int(end_port)
        self.timeout = timeout
        self.max_threads = max_threads
        self.banner_grab = banner_grab
        self.results: List[PortResult] = []
        self.lock = threading.Lock()
        self.scan_stats = {
            'total_ports': 0,
            'scanned_ports': 0,
            'open_ports': 0,
            'start_time': 0,
            'end_time': 0
        }

    def scan_ports(self):
        """Perform the port scan with multithreading"""
        self.scan_stats['start_time'] = time.time()
        self.scan_stats['total_ports'] = self.end_port - self.start_port + 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, port): port 
                for port in range(self.start_port, self.end_port + 1)
            }

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    with self.lock:
                        self.results.append(result)
                        self.scan_stats['scanned_ports'] += 1
                        if result.is_open:
                            self.scan_stats['open_ports'] += 1
                except Exception as e:
                    with self.lock:
                        self.results.append(PortResult(port, False, f"Error: {str(e)}"))
                        self.scan_stats['scanned_ports'] += 1

        self.scan_stats['end_time'] = time.time()

    def _scan_port(self, port: int) -> PortResult:
        """Scan an individual port"""
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.ip_address, port))
                
                if result == 0:
                    banner = None
                    if self.banner_grab:
                        try:
                            banner = sock.recv(1024).decode(errors='ignore').strip()
                            if not banner:
                                banner = None
                        except (socket.timeout, socket.error):
                            pass
                    
                    response_time = time.time() - start_time
                    return PortResult(port, True, banner, response_time)
                else:
                    return PortResult(port, False)
        except socket.timeout:
            return PortResult(port, False, "Timeout")
        except Exception as e:
            return PortResult(port, False, f"Error: {str(e)}")

    def print_results(self):
        """Print formatted scan results"""
        open_ports = sorted([r.port for r in self.results if r.is_open])
        closed_ports = sorted([r.port for r in self.results if not r.is_open])
        
        print("\nScan Results:")
        print(f"Target: {self.ip_address}")
        print(f"Port Range: {self.start_port}-{self.end_port}")
        print(f"Open Ports ({len(open_ports)}): {open_ports}")
        
        if self.banner_grab:
            print("\nDetailed Open Ports:")
            print("{:<8} {:<15} {:<50}".format("Port", "Response Time", "Banner"))
            print("-" * 75)
            for result in sorted(self.results, key=lambda x: x.port):
                if result.is_open:
                    banner = result.banner if result.banner else "No banner"
                    print("{:<8} {:<15.4f} {:<50}".format(
                        result.port, 
                        result.response_time if result.response_time else 0,
                        banner[:47] + '...' if banner and len(banner) > 50 else banner
                    ))

        self._print_stats()

    def _print_stats(self):
        """Print scan statistics"""
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        ports_per_sec = self.scan_stats['scanned_ports'] / duration if duration > 0 else 0
        
        print("\nScan Statistics:")
        print(f"- Ports scanned: {self.scan_stats['scanned_ports']}/{self.scan_stats['total_ports']}")
        print(f"- Open ports found: {self.scan_stats['open_ports']}")
        print(f"- Scan duration: {duration:.2f} seconds")
        print(f"- Scan speed: {ports_per_sec:.1f} ports/second")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Industrial-Grade Port Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("ip_address", help="Target IP address")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                       help="Connection timeout in seconds")
    parser.add_argument("-j", "--threads", type=int, default=100,
                       help="Maximum number of threads")
    parser.add_argument("-b", "--banner", action="store_true",
                       help="Enable banner grabbing")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        scanner = PortScanner(
            ip_address=args.ip_address,
            start_port=args.start_port,
            end_port=args.end_port,
            timeout=args.timeout,
            max_threads=args.threads,
            banner_grab=args.banner
        )
        
        print(f"Scanning {args.ip_address} ports {args.start_port}-{args.end_port}...")
        scanner.scan_ports()
        scanner.print_results()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
