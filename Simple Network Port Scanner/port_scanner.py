#!/usr/bin/env python3
"""
Simple Industrial-Grade Port Scanner with:
- Asynchronous I/O for high speed scanning
- Comprehensive error handling with custom exceptions
- Configurable timeouts
- Banner grabbing
- Generator-based iteration over results
- Dunder methods for pythonic usage
"""

import sys
import time
import argparse
import asyncio
from dataclasses import dataclass
from typing import List, Optional, AsyncGenerator

class PortScanError(Exception):
    """Custom exception for Port Scan errors"""
    pass

@dataclass
class PortResult:
    port: int
    is_open: bool
    banner: Optional[str] = None
    response_time: Optional[float] = None

    def __bool__(self) -> bool:
        return self.is_open
        
    def __str__(self) -> str:
        banner_display = self.banner[:47] + '...' if self.banner and len(self.banner) > 50 else (self.banner or "No banner")
        return f"{self.port:<8} {self.response_time or 0:<15.4f} {banner_display:<50}"

class PortScanner:
    def __init__(self, ip_address: str, start_port: int, end_port: int, 
                 timeout: float = 1.0, max_concurrency: int = 1000, 
                 banner_grab: bool = True):
        self.ip_address = ip_address
        
        if start_port > end_port or start_port < 1 or end_port > 65535:
            raise PortScanError(f"Invalid port range: {start_port}-{end_port}")
            
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.banner_grab = banner_grab
        self.results: List[PortResult] = []
        self.scan_stats = {
            'total_ports': 0,
            'scanned_ports': 0,
            'open_ports': 0,
            'start_time': 0.0,
            'end_time': 0.0
        }
        self._semaphore = asyncio.Semaphore(self.max_concurrency)

    def __len__(self) -> int:
        """Return the number of open ports"""
        return self.scan_stats['open_ports']
        
    def __iter__(self):
        """Iterate over open ports"""
        return (r for r in self.results if r.is_open)

    def __enter__(self):
        self.scan_stats['start_time'] = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.scan_stats['end_time'] = time.time()

    def generate_ports(self):
        """Yield port numbers to scan to save memory"""
        for p in range(self.start_port, self.end_port + 1):
            yield p

    async def scan_ports(self):
        """Perform the port scan asynchronously"""
        self.scan_stats['start_time'] = time.time()
        ports = list(self.generate_ports())
        self.scan_stats['total_ports'] = len(ports)

        tasks = [self._scan_port_with_semaphore(port) for port in ports]
        
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                self.results.append(result)
                self.scan_stats['scanned_ports'] += 1
                if bool(result):
                    self.scan_stats['open_ports'] += 1
            except Exception as e:
                # Should be caught by internal error handling, but just in case
                print(f"Unexpected error: {e}", file=sys.stderr)

        self.scan_stats['end_time'] = time.time()

    async def _scan_port_with_semaphore(self, port: int) -> PortResult:
        async with self._semaphore:
            return await self._scan_port(port)

    async def _scan_port(self, port: int) -> PortResult:
        """Scan an individual port"""
        start_time = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip_address, port), 
                timeout=self.timeout
            )
            
            banner = None
            if self.banner_grab:
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    banner = data.decode(errors='ignore').strip()
                    if not banner:
                        banner = None
                except (asyncio.TimeoutError, ConnectionResetError, OSError):
                    pass
            
            writer.close()
            await writer.wait_closed()
            
            response_time = time.time() - start_time
            return PortResult(port, True, banner, response_time)
            
        except asyncio.TimeoutError:
            return PortResult(port, False, "Timeout")
        except (ConnectionRefusedError, OSError) as e:
            return PortResult(port, False, f"Error: {str(e)}")
        except Exception as e:
            return PortResult(port, False, f"Error: {str(e)}")

    def print_results(self):
        """Print formatted scan results using dunder methods"""
        open_ports = sorted([r.port for r in self]) # Uses __iter__ and __bool__
        
        print("\nScan Results:")
        print(f"Target: {self.ip_address}")
        print(f"Port Range: {self.start_port}-{self.end_port}")
        print(f"Open Ports ({len(self)}): {open_ports}") # Uses __len__
        
        if self.banner_grab and len(self) > 0:
            print("\nDetailed Open Ports:")
            print("{:<8} {:<15} {:<50}".format("Port", "Response Time", "Banner"))
            print("-" * 75)
            for result in sorted(self, key=lambda x: x.port):
                print(result) # Uses __str__

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
        description="Simple Industrial-Grade Port Scanner (Async)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("ip_address", help="Target IP address")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                       help="Connection timeout in seconds")
    parser.add_argument("-j", "--threads", type=int, default=1000,
                       help="Maximum concurrency level (formerly threads)")
    parser.add_argument("-b", "--banner", action="store_true",
                       help="Enable banner grabbing")
    return parser.parse_args()

async def async_main():
    args = parse_arguments()
    
    try:
        with PortScanner(
            ip_address=args.ip_address,
            start_port=args.start_port,
            end_port=args.end_port,
            timeout=args.timeout,
            max_concurrency=args.threads,
            banner_grab=args.banner
        ) as scanner:
            print(f"Scanning {args.ip_address} ports {args.start_port}-{args.end_port}...")
            await scanner.scan_ports()
            scanner.print_results()
            
    except PortScanError as e:
        print(f"Configuration Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()) # type: ignore
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
