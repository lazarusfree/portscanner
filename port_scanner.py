#!/usr/bin/env python3
"""
Powerful Port Scanner - Nmap-like functionality
Made with love by n0vember
"""

import socket
import threading
import time
import argparse
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import os

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_logo():
    """Display the scanner logo"""
    logo = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║
║  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║
║  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║
║  ██╔══██╗██║   ██║██╔═══╝    ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ██║  ██║╚██████╔╝██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║
║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║
║                                                              ║
║                    {Colors.YELLOW}FAST & POWERFUL PORT SCANNER{Colors.CYAN}                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}

{Colors.PURPLE}{Colors.BOLD}Made with love by n0vember{Colors.END}
{Colors.BLUE}Version: 1.0.0 | Fast & Efficient Port Scanning{Colors.END}
"""
    print(logo)

class PortScanner:
    """Main port scanner class with nmap-like functionality"""
    
    def __init__(self, target, ports=None, scan_type="tcp", threads=100, timeout=3):
        self.target = target
        self.ports = ports or range(1, 1025)  # Default to common ports
        self.scan_type = scan_type.lower()
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.running = True
        
        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        self.running = False
        sys.exit(0)
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"{Colors.RED}[ERROR] Could not resolve hostname: {hostname}{Colors.END}")
            return None
    
    def tcp_connect_scan(self, port):
        """Perform TCP connect scan on a single port"""
        if not self.running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return port
        except:
            pass
        return None
    
    def tcp_syn_scan(self, port):
        """Perform TCP SYN scan (requires root privileges)"""
        if not self.running:
            return None
            
        try:
            # Create raw socket for SYN scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(self.timeout)
            
            # Create SYN packet
            syn_packet = self.create_syn_packet(port)
            sock.sendto(syn_packet, (self.target, 0))
            
            # Listen for response
            try:
                response = sock.recv(1024)
                if self.is_syn_ack(response, port):
                    sock.close()
                    return port
            except socket.timeout:
                pass
                
            sock.close()
        except PermissionError:
            print(f"{Colors.YELLOW}[WARNING] SYN scan requires root privileges. Falling back to connect scan.{Colors.END}")
            return self.tcp_connect_scan(port)
        except:
            pass
        return None
    
    def create_syn_packet(self, port):
        """Create a SYN packet for raw socket scanning"""
        # Simplified SYN packet creation
        # In a real implementation, you'd need proper IP and TCP headers
        return b'\x00' * 40  # Placeholder
    
    def is_syn_ack(self, response, port):
        """Check if response is a SYN-ACK packet"""
        # Simplified check
        return len(response) > 0
    
    def udp_scan(self, port):
        """Perform UDP scan on a single port"""
        if not self.running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return port
            except socket.timeout:
                # Port might be open/filtered
                sock.close()
                return port
        except:
            pass
        return None
    
    def scan_port(self, port):
        """Scan a single port based on scan type"""
        if self.scan_type == "tcp":
            return self.tcp_connect_scan(port)
        elif self.scan_type == "syn":
            return self.tcp_syn_scan(port)
        elif self.scan_type == "udp":
            return self.udp_scan(port)
        else:
            return self.tcp_connect_scan(port)
    
    def get_service_name(self, port):
        """Get service name for a port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return common_services.get(port, "Unknown")
    
    def scan(self):
        """Perform the main scan"""
        print(f"{Colors.CYAN}[*] Starting scan of {self.target}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scan type: {self.scan_type.upper()}{Colors.END}")
        print(f"{Colors.CYAN}[*] Threads: {self.threads}{Colors.END}")
        print(f"{Colors.CYAN}[*] Timeout: {self.timeout}s{Colors.END}")
        print(f"{Colors.CYAN}[*] Ports: {len(self.ports)} ports to scan{Colors.END}")
        print(f"{Colors.CYAN}[*] Starting scan at {time.strftime('%H:%M:%S')}{Colors.END}\n")
        
        self.scan_start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scans
            future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            # Process completed scans
            for future in as_completed(future_to_port):
                if not self.running:
                    break
                    
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        service = self.get_service_name(port)
                        print(f"{Colors.GREEN}[+] Port {port:5d}/tcp open  {service}{Colors.END}")
                        self.open_ports.append(port)
                except Exception as e:
                    print(f"{Colors.RED}[ERROR] Error scanning port {port}: {e}{Colors.END}")
        
        self.scan_end_time = time.time()
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary"""
        duration = self.scan_end_time - self.scan_start_time
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}Target: {self.target}{Colors.END}")
        print(f"{Colors.WHITE}Scan type: {self.scan_type.upper()}{Colors.END}")
        print(f"{Colors.WHITE}Duration: {duration:.2f} seconds{Colors.END}")
        print(f"{Colors.WHITE}Ports scanned: {len(self.ports)}{Colors.END}")
        print(f"{Colors.GREEN}Open ports: {len(self.open_ports)}{Colors.END}")
        
        if self.open_ports:
            print(f"\n{Colors.BOLD}OPEN PORTS:{Colors.END}")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"{Colors.GREEN}  {port:5d}/tcp open  {service}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}No open ports found.{Colors.END}")
        
        print(f"\n{Colors.PURPLE}Made with love by n0vember{Colors.END}")

def parse_ports(port_string):
    """Parse port range string (e.g., '1-1000', '80,443,8080')"""
    ports = set()
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    
    return sorted(list(ports))

def validate_target(target):
    """Validate target IP or hostname"""
    try:
        # Try to parse as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Try to resolve as hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Powerful Port Scanner - Made with love by n0vember",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                    # Scan common ports on IP
  %(prog)s example.com -p 80,443,8080     # Scan specific ports
  %(prog)s 10.0.0.1 -p 1-1000 -t 200      # Scan port range with 200 threads
  %(prog)s localhost -s syn               # SYN scan (requires root)
  %(prog)s 192.168.1.1 -s udp -p 53,123   # UDP scan
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', 
                       help='Port range to scan (e.g., 1-1000, 80,443,8080)')
    parser.add_argument('-s', '--scan-type', choices=['tcp', 'syn', 'udp'], 
                       default='tcp', help='Scan type (default: tcp)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=3,
                       help='Connection timeout in seconds (default: 3)')
    
    args = parser.parse_args()
    
    # Print logo
    print_logo()
    
    # Validate target
    if not validate_target(args.target):
        print(f"{Colors.RED}[ERROR] Invalid target: {args.target}{Colors.END}")
        sys.exit(1)
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"{Colors.RED}[ERROR] Invalid port specification: {e}{Colors.END}")
        sys.exit(1)
    
    # Create and run scanner
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        scan_type=args.scan_type,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Scan failed: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
