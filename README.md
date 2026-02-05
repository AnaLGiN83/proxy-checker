# Proxy Checker

Cross-platform proxy checker with **TLS freeze (censorship) detection**.

## Features

- **Proxy validation** — verifies proxy connectivity and retrieves external IP
- **TLS freeze detection** — detects DPI-based censorship by identifying connections that stall after ~16-20KB
- **Concurrent checking** — checks multiple proxies in parallel
- **Color-coded output** — visual status indication (green/red)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python proxy_checker.py proxy-list.txt
```

### With Options

```bash
# Verbose output with 10 concurrent checks
python proxy_checker.py proxy-list.txt -c 10 -v

# Save working proxies to file
python proxy_checker.py proxy-list.txt -o working.txt

# Custom timeout
python proxy_checker.py proxy-list.txt --timeout 60
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `input_file` | File with proxy list | required |
| `-o, --output` | Output file for working proxies | none |
| `-c, --concurrency` | Number of concurrent checks | 5 |
| `--timeout-connect` | Connection timeout (seconds) | 10 |
| `--timeout` | Total timeout (seconds) | 30 |
| `-v, --verbose` | Verbose output | false |

## Proxy File Format

One proxy per line in format:

```
host:port:username:password
```

Example:

```
proxy.example.com:8080:user:pass123
192.168.1.100:3128:admin:secret
```

Lines starting with `#` are treated as comments.

## Status Codes

| Status | Color | Description |
|--------|-------|-------------|
| **OK** | 🟢 Green | Proxy works normally |
| **TLS_FREEZE** | 🔴 Red | Censorship detected (connection stalled at 16-20KB) |
| **TIMEOUT** | 🔴 Red | Connection timed out |
| **ERROR** | 🔴 Red | Connection or other error |
| **AUTH_FAILED** | 🔴 Red | Proxy authentication failed |

## TLS Freeze Detection

The tool detects DPI-based censorship by identifying a characteristic pattern:

**TLS connections that stall after ~16-20KB of data transfer.**

This is a common behavior of Deep Packet Inspection (DPI) systems that:
1. Allow the TLS handshake to complete
2. Start passing encrypted data
3. Then block/throttle the connection after analyzing initial packets

The detection works by:
- Downloading data through HTTPS (TLS)
- Monitoring for stalls (no data for 5+ seconds)
- Flagging connections that freeze in the 14-25KB range

## Example Output

```
Loaded 2 proxies for checking
Parameters: concurrency=5, timeout=30.0s
TLS freeze detection: stall at 14-25KB after 5.0s
--------------------------------------------------
proxy1.example.com:8080: [OK]
  └─ IP: 203.0.113.45
  └─ Response time: 1.65s
proxy2.example.com:3128: [TLS_FREEZE (censorship detected)]
  └─ IP: 151.236.165.163
  └─ Response time: 3.25s
  └─ Bytes before freeze: 17.5 KB
  └─ Error: TLS freeze at 17.5KB

==================================================
SUMMARY:
  Total checked: 2
  Working (OK):       1
  TLS Freeze (censor): 1
  Timeout:            0
  Errors:             0
==================================================
```

## License

MIT
