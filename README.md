# Proxy Checker

Cross-platform proxy checker with censorship/throttling detection.

## Features

- **Proxy validation** — verifies proxy connectivity and retrieves external IP
- **Speed measurement** — measures download speed through proxy
- **Censorship detection** — detects traffic throttling (slow connections that "load forever")
- **Concurrent checking** — checks multiple proxies in parallel
- **Color-coded output** — visual status indication (green/yellow/red)

## Installation

```bash
pip install -r requirements.txt
```

Or install directly:

```bash
pip install aiohttp
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

# Custom thresholds
python proxy_checker.py proxy-list.txt --timeout 60 --slow-time 20 --slow-speed 30
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `input_file` | File with proxy list | required |
| `-o, --output` | Output file for working proxies | none |
| `-c, --concurrency` | Number of concurrent checks | 5 |
| `--timeout-connect` | Connection timeout (seconds) | 10 |
| `--timeout` | Total timeout (seconds) | 30 |
| `--slow-time` | Time threshold for slow detection (seconds) | 15 |
| `--slow-speed` | Speed threshold for slow detection (KB/s) | 50 |
| `-v, --verbose` | Verbose output | false |
| `--include-slow` | Include slow proxies when saving | false |

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
| **SLOW** | 🟡 Yellow | Proxy works but slow (possible censorship/throttling) |
| **TIMEOUT** | 🔴 Red | Connection timed out |
| **ERROR** | 🔴 Red | Connection or other error |
| **AUTH_FAILED** | 🔴 Red | Proxy authentication failed |

## Censorship Detection

The tool detects potential censorship/throttling when:

1. **Response time** exceeds the threshold (default: 15 seconds)
2. **Download speed** falls below the threshold (default: 50 KB/s)

These thresholds can be adjusted via `--slow-time` and `--slow-speed` arguments.

## Example Output

```
Loaded 3 proxies for checking
Parameters: concurrency=5, timeout=30.0s
Censorship thresholds: time>15.0s or speed<50.0KB/s
--------------------------------------------------
proxy1.example.com:8080: [OK]
proxy2.example.com:3128: [SLOW (possible censorship)]
  └─ IP: 203.0.113.45
  └─ Response time: 18.34s
  └─ Download speed: 12.5 KB/s
proxy3.example.com:1080: [TIMEOUT]
  └─ Error: Connection timeout (30.0s)

==================================================
SUMMARY:
  Total checked: 3
  Working (OK):    1
  Slow (SLOW):     1
  Timeout:         1
  Errors:          0
==================================================
```

## License

MIT
