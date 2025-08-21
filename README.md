# Port Scanner - Made with love by n0vember

A powerful, fast, and efficient port scanner with nmap-like functionality, built in Python.

## Features

- 🚀 **Fast & Efficient**: Multi-threaded scanning for high performance
- 🎨 **Beautiful UI**: Colored terminal output with ASCII art logo
- 🔍 **Multiple Scan Types**: TCP connect, SYN, and UDP scanning
- 🎯 **Flexible Targeting**: Support for IP addresses and hostnames
- 📊 **Detailed Output**: Service detection and comprehensive scan summaries
- ⚡ **Configurable**: Customizable threads, timeouts, and port ranges
- 🛡️ **Graceful Handling**: Proper signal handling and error management

## Installation

No installation required! Just make sure you have Python 3.6+ installed:

```bash
python3 --version
```

## Usage

### Basic Usage

```bash
# Scan common ports (1-1024) on a target
./port_scanner.py 192.168.1.1

# Scan a specific hostname
./port_scanner.py example.com

# Scan localhost
./port_scanner.py localhost
```

### Advanced Usage

```bash
# Scan specific ports
./port_scanner.py 192.168.1.1 -p 80,443,8080

# Scan a port range
./port_scanner.py 10.0.0.1 -p 1-1000

# Use more threads for faster scanning
./port_scanner.py 192.168.1.1 -t 200

# SYN scan (requires root privileges)
sudo ./port_scanner.py 192.168.1.1 -s syn

# UDP scan
./port_scanner.py 192.168.1.1 -s udp -p 53,123

# Custom timeout
./port_scanner.py 192.168.1.1 --timeout 5
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address or hostname | Required |
| `-p, --ports` | Port range to scan (e.g., 1-1000, 80,443,8080) | 1-1024 |
| `-s, --scan-type` | Scan type: tcp, syn, udp | tcp |
| `-t, --threads` | Number of threads | 100 |
| `--timeout` | Connection timeout in seconds | 3 |

## Scan Types

### TCP Connect Scan (`-s tcp`)
- Standard TCP connection scan
- Works without root privileges
- Most reliable but can be detected by firewalls

### SYN Scan (`-s syn`)
- Stealthy SYN packet scan
- Requires root privileges
- Less likely to be logged by target systems

### UDP Scan (`-s udp`)
- UDP packet scanning
- Useful for discovering UDP services
- Can be slower due to UDP nature

## Examples

### Quick Network Discovery
```bash
# Scan your local network
./port_scanner.py 192.168.1.1 -p 1-1000 -t 200
```

### Web Server Check
```bash
# Check common web ports
./port_scanner.py example.com -p 80,443,8080,8443
```

### Database Ports
```bash
# Check database services
./port_scanner.py 192.168.1.100 -p 3306,5432,6379,27017
```

### Full Port Scan
```bash
# Scan all ports (takes longer)
./port_scanner.py 192.168.1.1 -p 1-65535 -t 500
```

## Output Format

The scanner provides real-time output showing:
- Open ports with service names
- Scan progress and timing
- Comprehensive summary at the end

Example output:
```
[+] Port    22/tcp open  SSH
[+] Port    80/tcp open  HTTP
[+] Port   443/tcp open  HTTPS
[+] Port  3306/tcp open  MySQL

============================================================
SCAN SUMMARY
============================================================
Target: 192.168.1.1
Scan type: TCP
Duration: 2.34 seconds
Ports scanned: 1024
Open ports: 4

OPEN PORTS:
    22/tcp open  SSH
    80/tcp open  HTTP
   443/tcp open  HTTPS
  3306/tcp open  MySQL

Made with love by n0vember
```

## Performance Tips

1. **Increase threads** for faster scanning: `-t 200`
2. **Reduce timeout** for faster results: `--timeout 1`
3. **Use SYN scan** when possible (requires root)
4. **Target specific ports** instead of full ranges when possible

## Security Notice

⚠️ **Important**: This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target system. Unauthorized port scanning may be illegal in some jurisdictions.

## Requirements

- Python 3.6 or higher
- Standard library modules (no external dependencies)
- Root privileges for SYN scanning

## Troubleshooting

### Permission Denied for SYN Scan
```bash
# Use sudo for SYN scans
sudo ./port_scanner.py 192.168.1.1 -s syn
```

### Slow Scanning
```bash
# Increase threads and reduce timeout
./port_scanner.py 192.168.1.1 -t 200 --timeout 1
```

### Hostname Resolution Issues
```bash
# Use IP address instead of hostname
./port_scanner.py 8.8.8.8
```

## License

This project is open source and available under the MIT License.

---

**Made with love by n0vember** ❤️
