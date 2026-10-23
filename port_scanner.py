#!/usr/bin/env python3
"""
Powerful Port Scanner - asynchronous TCP connect scanner
Made with love by n0vember
"""

import argparse
import asyncio
import errno
import ipaddress
import os
import socket
import struct
import sys
import time

try:
    import resource  # POSIX only
except ImportError:
    resource = None

# Port states
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
ERROR = "error"  # local failure (out of sockets, ...): says nothing about the target

MAX_PORT = 65535
DEFAULT_CONCURRENCY = 500
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1


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

    @classmethod
    def disable(cls):
        """Blank every code so output stays clean when piped or logged"""
        for name in [n for n in vars(cls) if n.isupper()]:
            setattr(cls, name, '')


def use_color():
    """Color only on a real terminal, and never when NO_COLOR is set"""
    return sys.stdout.isatty() and not os.environ.get('NO_COLOR')

def print_logo():
    """Display the scanner logo"""
    logo = f"""
{Colors.CYAN}{Colors.BOLD}
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                     ║
║  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║
║  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║
║  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║
║  ██╔══██╗██║   ██║██╔═══╝    ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ██║  ██║╚██████╔╝██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║
║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║
║                                                                                                     ║
║                    {Colors.YELLOW}FAST & POWERFUL PORT SCANNER{Colors.CYAN}                         ║
║                                                                                                     ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}

{Colors.PURPLE}{Colors.BOLD}Made with love by n0vember{Colors.END}
{Colors.BLUE}Version: 1.0.1 | Fast & Efficient Port Scanning{Colors.END}
"""
    print(logo)


# --- error classification -------------------------------------------------
# A failed connect() is only "closed" when the target actively refused it.
# Silence or "unreachable" is filtered; running out of local sockets or
# buffers is our own problem and must never be reported as a port state.

_REFUSED_ERRNO = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED}
_FILTERED_ERRNO = {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
                   errno.EHOSTDOWN, errno.ENETDOWN}
_LOCAL_ERRNO = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM,
                errno.EADDRINUSE, errno.EADDRNOTAVAIL}

# Windows reports the same conditions through winerror / WSA codes
_REFUSED_WIN = {1225, 10061, 10054, 10053}
_FILTERED_WIN = {121, 1231, 1232, 10051, 10060, 10065, 10050, 10052}
_LOCAL_WIN = {10024, 10048, 10049, 10055}


def classify_connect_error(exc):
    """Map an exception from a connect attempt to (state, reason)"""
    if isinstance(exc, asyncio.TimeoutError):
        return FILTERED, "no-response"

    winerror = getattr(exc, 'winerror', None)
    code = getattr(exc, 'errno', None)

    if winerror in _LOCAL_WIN or (winerror is None and code in _LOCAL_ERRNO):
        return ERROR, "local-resource"
    if isinstance(exc, PermissionError):  # local policy; the target never saw a packet
        return ERROR, "access-denied"
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError,
                        ConnectionAbortedError)):
        return CLOSED, "refused"
    if winerror in _REFUSED_WIN or (winerror is None and code in _REFUSED_ERRNO):
        return CLOSED, "refused"
    if winerror in _FILTERED_WIN or (winerror is None and code in _FILTERED_ERRNO):
        return FILTERED, "unreachable"
    return ERROR, f"unexpected:{type(exc).__name__}"


def tune_socket(sock, timeout):
    """Windows keeps resending the SYN after an RST, so a refused port takes
    about 2 s to fail, longer than any sane timeout, and closed ports would be
    misread as filtered. Turning off SYN retransmission makes a refusal
    immediate. Returns False when the tuning is unavailable."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class TcpInitialRto(ctypes.Structure):
            _fields_ = [("Rtt", ctypes.c_ushort),
                        ("MaxSynRetransmissions", ctypes.c_ubyte)]

        sio_tcp_initial_rto = 0x98000011
        no_syn_retransmissions = 254
        params = TcpInitialRto(min(max(int(timeout * 1000), 1), 65534),
                               no_syn_retransmissions)
        returned = wintypes.DWORD(0)
        ws2 = ctypes.WinDLL("ws2_32", use_last_error=True)
        rc = ws2.WSAIoctl(sock.fileno(), sio_tcp_initial_rto,
                          ctypes.byref(params), ctypes.sizeof(params),
                          None, 0, ctypes.byref(returned), None, None)
        return rc == 0
    except Exception:
        return False


def max_safe_concurrency():
    """Open-file ceiling minus headroom (POSIX); None when there is no limit"""
    if resource is None:
        return None
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ValueError, OSError):
        return None
    if soft == resource.RLIM_INFINITY:
        return None
    return max(soft - 64, 1)


def resolve_target(target):
    """Resolve a hostname or IP once. Returns (family, ip_string)."""
    try:
        ip = ipaddress.ip_address(target)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        return family, str(ip)
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"could not resolve hostname: {target} ({e})")
    family, _, _, _, sockaddr = info[0]
    return family, sockaddr[0]


def validate_target(target):
    """Validate target IP or hostname"""
    try:
        resolve_target(target)
        return True
    except ValueError:
        return False


def parse_ports(port_string):
    """Parse a port string (e.g., '1-1000', '80,443,8080') into a sorted list.

    Raises ValueError on malformed input, ports outside 1-65535 and
    reversed ranges, so a bad request can never turn into a different scan."""
    ports = set()

    for part in port_string.split(','):
        part = part.strip()
        if not part:
            raise ValueError("empty port entry")
        if '-' in part:
            bounds = part.split('-')
            if len(bounds) != 2:
                raise ValueError(f"invalid port range: {part!r}")
            start, end = (_parse_port(b, part) for b in bounds)
            if start > end:
                raise ValueError(f"reversed port range: {part!r} (use {end}-{start})")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(part, part))

    return sorted(ports)


def _parse_port(text, context):
    try:
        port = int(text)
    except ValueError:
        raise ValueError(f"invalid port {text.strip()!r} in {context!r}")
    check_port(port)
    return port


def check_port(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= MAX_PORT:
        raise ValueError(f"port out of range 1-{MAX_PORT}: {port!r}")


class PortScanner:
    """Asynchronous TCP connect scanner reporting open/closed/filtered"""

    def __init__(self, target, ports=None, scan_type="tcp",
                 concurrency=DEFAULT_CONCURRENCY, timeout=DEFAULT_TIMEOUT,
                 retries=DEFAULT_RETRIES, threads=None):
        self.target = target
        self.scan_type = scan_type.lower()
        if self.scan_type != "tcp":
            raise ValueError(f"unsupported scan type {scan_type!r}: only 'tcp' is implemented")

        # An explicit empty list is an error, not a request for the default
        self.ports = list(range(1, 1025)) if ports is None else list(ports)
        if not self.ports:
            raise ValueError("no ports to scan")
        for port in self.ports:
            check_port(port)

        if threads is not None:  # old name for concurrency
            concurrency = threads
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if retries < 0:
            raise ValueError("retries cannot be negative")

        ceiling = max_safe_concurrency()
        self.concurrency_clamped = ceiling is not None and concurrency > ceiling
        self.concurrency = min(concurrency, ceiling) if ceiling else concurrency
        self.timeout = timeout
        self.retries = retries

        self.family, self.ip = resolve_target(target)

        self.results = {}   # port -> state
        self.reasons = {}   # port -> why
        self.open_ports = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.interrupted = False
        self.fast_refusal = None  # set in run(): can closed ports be told from filtered?

    # -- probing ----------------------------------------------------------

    def _address(self, port):
        # IPv6 sockaddrs are 4-tuples; the Windows proactor loop insists on it
        if self.family == socket.AF_INET6:
            return (self.ip, port, 0, 0)
        return (self.ip, port)

    async def _connect(self, loop, port):
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            tune_socket(sock, self.timeout)
            await asyncio.wait_for(loop.sock_connect(sock, self._address(port)), self.timeout)
            # Connected: reset on close instead of lingering in TIME_WAIT,
            # which would exhaust local ports on big scans
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            return OPEN, "connected"
        except (asyncio.TimeoutError, OSError) as e:
            return classify_connect_error(e)
        finally:
            sock.close()

    async def probe(self, port):
        """Probe one port; retries local resource errors with backoff"""
        loop = asyncio.get_running_loop()
        for attempt in range(4):
            state, reason = await self._connect(loop, port)
            if state != ERROR or reason != "local-resource":
                break
            await asyncio.sleep(0.05 * 2 ** attempt)
        return state, reason

    async def _run_pass(self, ports):
        queue = iter(ports)

        async def worker():
            for port in queue:  # shared iterator: safe, the loop is single-threaded
                state, reason = await self.probe(port)
                self._record(port, state, reason)

        count = min(self.concurrency, len(ports))
        await asyncio.gather(*(worker() for _ in range(count)))

    def _record(self, port, state, reason):
        previous = self.results.get(port)
        self.results[port] = state
        self.reasons[port] = reason
        if state == OPEN and previous != OPEN:
            self.open_ports.append(port)
            print(f"{Colors.GREEN}[+] Port {port:5d}/tcp open  "
                  f"{self.get_service_name(port)}{Colors.END}", flush=True)

    async def run(self):
        """Scan every port, then re-probe the inconclusive ones"""
        probe_sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.fast_refusal = tune_socket(probe_sock, self.timeout)
        probe_sock.close()
        if not self.fast_refusal and self.timeout < 2.5:
            print(f"{Colors.YELLOW}[!] This system retries refused connections for ~2 s; "
                  f"closed ports may be reported as filtered unless --timeout >= 2.5"
                  f"{Colors.END}")

        await self._run_pass(self.ports)
        for _ in range(self.retries):
            pending = [p for p in self.ports if self.results.get(p) in (FILTERED, ERROR)]
            if not pending:
                break
            await self._run_pass(pending)

    # -- reporting --------------------------------------------------------

    def get_service_name(self, port):
        """Get service name for a port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return common_services.get(port, "Unknown")

    def count(self, state):
        return sum(1 for s in self.results.values() if s == state)

    def scan(self):
        """Perform the main scan; returns the sorted open ports"""
        print(f"{Colors.CYAN}[*] Starting scan of {self.target}"
              f"{'' if self.target == self.ip else f' ({self.ip})'}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scan type: {self.scan_type.upper()} connect (asyncio){Colors.END}")
        print(f"{Colors.CYAN}[*] Concurrency: {self.concurrency}{Colors.END}")
        print(f"{Colors.CYAN}[*] Timeout: {self.timeout}s, retries: {self.retries}{Colors.END}")
        print(f"{Colors.CYAN}[*] Ports: {len(self.ports)} ports to scan{Colors.END}")
        print(f"{Colors.CYAN}[*] Starting scan at {time.strftime('%H:%M:%S')}{Colors.END}\n")
        if self.concurrency_clamped:
            print(f"{Colors.YELLOW}[!] Concurrency lowered to {self.concurrency} "
                  f"(open-file limit){Colors.END}")

        self.scan_start_time = time.time()
        try:
            asyncio.run(self.run())
        except KeyboardInterrupt:
            self.interrupted = True
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user; results are partial{Colors.END}")
        finally:
            self.scan_end_time = time.time()

        self.print_summary()
        return sorted(self.open_ports)

    def print_summary(self):
        """Print scan summary"""
        duration = self.scan_end_time - self.scan_start_time
        scanned = len(self.results)

        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}Target: {self.target} ({self.ip}){Colors.END}")
        print(f"{Colors.WHITE}Scan type: {self.scan_type.upper()}{Colors.END}")
        print(f"{Colors.WHITE}Duration: {duration:.2f} seconds{Colors.END}")
        print(f"{Colors.WHITE}Ports scanned: {scanned} of {len(self.ports)}{Colors.END}")
        print(f"{Colors.GREEN}Open ports: {len(self.open_ports)}{Colors.END}")
        print(f"{Colors.WHITE}Closed: {self.count(CLOSED)}  "
              f"Filtered: {self.count(FILTERED)}  "
              f"Errors: {self.count(ERROR)}{Colors.END}")
        if self.count(ERROR):
            why = sorted({self.reasons[p] for p, s in self.results.items() if s == ERROR})
            print(f"{Colors.RED}[!] {self.count(ERROR)} ports could not be tested "
                  f"({', '.join(why)}); they are not counted as closed{Colors.END}")
            if "local-resource" in why:
                print(f"{Colors.RED}    lower --concurrency and rescan those ports{Colors.END}")

        if self.open_ports:
            print(f"\n{Colors.BOLD}OPEN PORTS:{Colors.END}")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"{Colors.GREEN}  {port:5d}/tcp open  {service}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}No open ports found.{Colors.END}")

        print(f"\n{Colors.PURPLE}Made with love by n0vember{Colors.END}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Powerful Port Scanner - Made with love by n0vember",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                    # Scan ports 1-1024 on IP
  %(prog)s example.com -p 80,443,8080     # Scan specific ports
  %(prog)s 10.0.0.1 -p 1-65535 -c 1000    # Scan every port, 1000 at a time
  %(prog)s localhost --timeout 0.3        # Faster on a LAN
        """
    )

    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Port range to scan (e.g., 1-1000, 80,443,8080)')
    parser.add_argument('-c', '--concurrency', '-t', '--threads', type=int,
                        dest='concurrency', default=DEFAULT_CONCURRENCY,
                        help=f'Simultaneous connection attempts (default: {DEFAULT_CONCURRENCY}; '
                             '-t/--threads is the old name)')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                        help=f'Per-connection timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--retries', type=int, default=DEFAULT_RETRIES,
                        help='Extra attempts for ports that did not answer '
                             f'(default: {DEFAULT_RETRIES})')

    args = parser.parse_args()

    if not use_color():
        Colors.disable()
    if hasattr(sys.stdout, 'reconfigure'):  # the logo is not ASCII; don't die on cp1252 pipes
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print_logo()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"{Colors.RED}[ERROR] Invalid port specification: {e}{Colors.END}")
        sys.exit(1)

    try:
        scanner = PortScanner(
            target=args.target,
            ports=ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            retries=args.retries,
        )
    except ValueError as e:
        print(f"{Colors.RED}[ERROR] {e}{Colors.END}")
        sys.exit(1)

    try:
        scanner.scan()
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Scan failed: {e}{Colors.END}")
        sys.exit(1)
    if scanner.interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
