# Port Scanner - Made with love by n0vember

A powerful, fast, and efficient port scanner with nmap-like functionality, built in Python.

## Features

- 🚀 **Fast**: asyncio TCP connect scanning with hundreds of connections in flight
- 🎯 **Accurate**: every port is reported `open`, `closed` (refused) or `filtered` (no answer); local failures such as running out of sockets are reported as errors, never as "closed"
- 🎨 **Beautiful UI**: Colored terminal output with ASCII art logo (colors turn off when piped or when `NO_COLOR` is set)
- 🌐 **Flexible Targeting**: IPv4/IPv6 addresses and hostnames, resolved once
- 📊 **Summary**: open/closed/filtered counts and a service-name hint from the port number
- ⚡ **Configurable**: concurrency, timeout, retries and port ranges
- 🛡️ **Strict input**: reversed or out-of-range ports are rejected instead of silently scanning something else

SYN and UDP scanning are not implemented yet.

## Installation

No installation required! Just make sure you have Python 3.8+ installed:

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

# More simultaneous connections
./port_scanner.py 192.168.1.1 -p 1-65535 -c 1000

# Custom timeout and retries
./port_scanner.py 192.168.1.1 --timeout 2 --retries 2
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address or hostname | Required |
| `-p, --ports` | Port range to scan (e.g., 1-1000, 80,443,8080) | 1-1024 |
| `-c, --concurrency` (`-t, --threads`) | Simultaneous connection attempts | 500 |
| `--timeout` | Per-connection timeout in seconds | 1 |
| `--retries` | Extra attempts for ports that did not answer | 1 |

Ports must be in 1-65535 and ranges must run low to high (`100-500`, not `500-100`); anything else is an error and nothing is scanned. Exit status is 1 on bad input and 130 if interrupted.

## How results are decided

The scanner is a TCP connect scan. Works without root privileges, and is visible in the target's logs.

| State | Meaning |
|-------|---------|
| `open` | the connection completed |
| `closed` | the target answered with a reset (connection refused) |
| `filtered` | no answer, or the network reported the host unreachable; re-probed `--retries` times before being reported |
| `error` | the scan could not test the port locally (out of sockets, access denied); never counted as closed |

If the summary shows errors, lower `--concurrency` and rescan. On Windows the scanner turns off SYN retransmission on its sockets so a refused port fails immediately instead of after ~2 s; if that is unavailable it warns that `--timeout` should be at least 2.5.

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

1. **Raise concurrency** for big ranges: `-c 1000` (it is capped by the open-file limit on Linux/macOS)
2. **Lower the timeout** on fast networks: `--timeout 0.3`; a timeout shorter than the round trip makes open ports look filtered
3. **Target specific ports** instead of full ranges when possible

## Security Notice

⚠️ **Important**: This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target system. Unauthorized port scanning may be illegal in some jurisdictions.

## Requirements

- Python 3.8 or higher
- Standard library modules (no external dependencies)
- `pytest` to run the tests (`python -m pytest tests`)

## Troubleshooting

### Slow Scanning
```bash
# More connections in flight, shorter timeout, no re-probing
./port_scanner.py 192.168.1.1 -c 1000 --timeout 0.5 --retries 0
```

### "could not be tested" errors in the summary
```bash
# The OS ran out of sockets: lower concurrency
./port_scanner.py 192.168.1.1 -c 200
```

### Hostname Resolution Issues
```bash
# Use IP address instead of hostname
./port_scanner.py 8.8.8.8
```

## License

This project is open source and available under the GPL-3.0.

---

**Made with love by n0vember** ❤️
