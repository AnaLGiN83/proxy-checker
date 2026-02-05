#!/usr/bin/env python3
"""
Cross-platform Proxy Checker
Checks proxy functionality and detects traffic throttling (censorship)
"""

import argparse
import asyncio
import time
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    import aiohttp
except ImportError:
    print("Required: pip install aiohttp")
    sys.exit(1)


class ProxyStatus(Enum):
    OK = "OK"
    TLS_FREEZE = "TLS_FREEZE (censorship detected)"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    AUTH_FAILED = "AUTH_FAILED"


@dataclass
class ProxyResult:
    proxy: str
    status: ProxyStatus
    response_time: Optional[float] = None
    bytes_before_freeze: Optional[int] = None  # Bytes downloaded before freeze
    error_message: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass
class ProxyConfig:
    host: str
    port: int
    username: str
    password: str

    @property
    def url(self) -> str:
        return f"http://{self.username}:{self.password}@{self.host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def parse_proxy_line(line: str) -> Optional[ProxyConfig]:
    """Parses a line in format host:port:username:password"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    parts = line.split(':')
    if len(parts) != 4:
        print(f"Invalid proxy format: {line}")
        return None

    host, port_str, username, password = parts
    try:
        port = int(port_str)
    except ValueError:
        print(f"Invalid port: {port_str}")
        return None

    return ProxyConfig(host=host, port=port, username=username, password=password)


def load_proxies(filepath: str) -> list[ProxyConfig]:
    """Loads proxy list from file"""
    proxies = []
    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {filepath}")
        return proxies

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            proxy = parse_proxy_line(line)
            if proxy:
                proxies.append(proxy)

    return proxies


# TLS freeze detection constants
FREEZE_MIN_BYTES = 14 * 1024  # 14KB - lower bound for freeze detection
FREEZE_MAX_BYTES = 25 * 1024  # 25KB - upper bound for freeze detection  
FREEZE_STALL_TIMEOUT = 5.0    # Seconds without data to consider it a freeze
CHUNK_SIZE = 1024             # Read in small chunks for precise detection


async def check_tls_freeze(
    session: aiohttp.ClientSession,
    proxy: ProxyConfig,
    test_url: str,
    total_timeout: float = 30.0,
) -> tuple[bool, int]:
    """
    Checks for TLS freeze pattern - when connection stalls after 16-20KB.
    
    Returns:
        (is_frozen, bytes_downloaded)
    """
    downloaded_bytes = 0
    last_chunk_time = time.perf_counter()
    
    try:
        async with session.get(
            test_url,
            proxy=proxy.url,
            ssl=True,  # Use TLS
            timeout=aiohttp.ClientTimeout(total=total_timeout, sock_read=FREEZE_STALL_TIMEOUT + 1)
        ) as response:
            if response.status != 200:
                return False, 0
            
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        response.content.read(CHUNK_SIZE),
                        timeout=FREEZE_STALL_TIMEOUT
                    )
                    
                    if not chunk:
                        # Download completed successfully
                        return False, downloaded_bytes
                    
                    downloaded_bytes += len(chunk)
                    last_chunk_time = time.perf_counter()
                    
                except asyncio.TimeoutError:
                    # Stall detected - check if it's in the freeze range
                    if FREEZE_MIN_BYTES <= downloaded_bytes <= FREEZE_MAX_BYTES:
                        return True, downloaded_bytes
                    # Stall outside freeze range - just timeout
                    return False, downloaded_bytes
                    
    except asyncio.TimeoutError:
        # Check if stall happened in freeze range
        if FREEZE_MIN_BYTES <= downloaded_bytes <= FREEZE_MAX_BYTES:
            return True, downloaded_bytes
        return False, downloaded_bytes
    except Exception:
        return False, downloaded_bytes


async def check_proxy(
    proxy: ProxyConfig,
    timeout_connect: float = 10.0,
    timeout_total: float = 30.0,
) -> ProxyResult:
    """
    Checks proxy for functionality and TLS freeze (censorship).
    
    TLS freeze detection:
    - Downloads data through HTTPS
    - Detects if connection stalls after ~16-20KB (characteristic of DPI censorship)
    """
    test_urls = [
        ("https://httpbin.org/ip", "origin"),  # Returns IP
        ("https://api.ipify.org?format=json", "ip"),  # Alternative service
    ]

    # URL for TLS freeze test - needs to return enough data (>25KB)
    freeze_test_url = "https://httpbin.org/bytes/102400"  # 100KB

    connector = aiohttp.TCPConnector(limit=1, force_close=True)
    timeout = aiohttp.ClientTimeout(
        connect=timeout_connect,
        total=timeout_total
    )

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:
            # Test 1: Connection check and IP retrieval
            ip_address = None
            start_time = time.perf_counter()

            for test_url, ip_key in test_urls:
                try:
                    async with session.get(
                        test_url,
                        proxy=proxy.url,
                        ssl=True
                    ) as response:
                        if response.status == 407:
                            return ProxyResult(
                                proxy=str(proxy),
                                status=ProxyStatus.AUTH_FAILED,
                                error_message="Proxy authentication failed"
                            )

                        if response.status == 200:
                            data = await response.json()
                            ip_address = data.get(ip_key)
                            break
                except Exception:
                    continue

            response_time = time.perf_counter() - start_time

            if ip_address is None:
                return ProxyResult(
                    proxy=str(proxy),
                    status=ProxyStatus.ERROR,
                    error_message="Failed to get IP through proxy"
                )

            # Test 2: TLS freeze detection
            is_frozen, bytes_downloaded = await check_tls_freeze(
                session, proxy, freeze_test_url, timeout_total
            )

            if is_frozen:
                return ProxyResult(
                    proxy=str(proxy),
                    status=ProxyStatus.TLS_FREEZE,
                    response_time=response_time,
                    bytes_before_freeze=bytes_downloaded,
                    ip_address=ip_address,
                    error_message=f"TLS freeze at {bytes_downloaded/1024:.1f}KB"
                )

            return ProxyResult(
                proxy=str(proxy),
                status=ProxyStatus.OK,
                response_time=response_time,
                ip_address=ip_address
            )

    except asyncio.TimeoutError:
        return ProxyResult(
            proxy=str(proxy),
            status=ProxyStatus.TIMEOUT,
            error_message=f"Connection timeout ({timeout_total}s)"
        )
    except aiohttp.ClientProxyConnectionError as e:
        return ProxyResult(
            proxy=str(proxy),
            status=ProxyStatus.ERROR,
            error_message=f"Proxy connection error: {e}"
        )
    except aiohttp.ClientError as e:
        return ProxyResult(
            proxy=str(proxy),
            status=ProxyStatus.ERROR,
            error_message=f"Client error: {e}"
        )
    except Exception as e:
        return ProxyResult(
            proxy=str(proxy),
            status=ProxyStatus.ERROR,
            error_message=f"Unknown error: {e}"
        )


def print_result(result: ProxyResult, verbose: bool = False) -> None:
    """Prints proxy check result"""
    status_colors = {
        ProxyStatus.OK: "\033[92m",           # Green
        ProxyStatus.TLS_FREEZE: "\033[91m",   # Red - censorship
        ProxyStatus.TIMEOUT: "\033[91m",      # Red
        ProxyStatus.ERROR: "\033[91m",        # Red
        ProxyStatus.AUTH_FAILED: "\033[91m"   # Red
    }
    reset = "\033[0m"

    color = status_colors.get(result.status, "")
    status_str = f"{color}[{result.status.value}]{reset}"

    print(f"{result.proxy}: {status_str}")

    if verbose or result.status != ProxyStatus.OK:
        if result.ip_address:
            print(f"  └─ IP: {result.ip_address}")
        if result.response_time is not None:
            print(f"  └─ Response time: {result.response_time:.2f}s")
        if result.bytes_before_freeze is not None:
            print(f"  └─ Bytes before freeze: {result.bytes_before_freeze/1024:.1f} KB")
        if result.error_message:
            print(f"  └─ Error: {result.error_message}")


async def check_proxies(
    proxies: list[ProxyConfig],
    concurrency: int = 5,
    timeout_connect: float = 10.0,
    timeout_total: float = 30.0,
    verbose: bool = False
) -> list[ProxyResult]:
    """Checks proxy list with limited concurrent requests"""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def check_with_semaphore(proxy: ProxyConfig) -> ProxyResult:
        async with semaphore:
            print(f"Checking {proxy}...", end=" ", flush=True)
            result = await check_proxy(
                proxy,
                timeout_connect=timeout_connect,
                timeout_total=timeout_total,
            )
            # Clear line and print result
            print("\r" + " " * 50 + "\r", end="")
            print_result(result, verbose)
            return result

    tasks = [check_with_semaphore(proxy) for proxy in proxies]
    results = await asyncio.gather(*tasks)

    return list(results)


def print_summary(results: list[ProxyResult]) -> None:
    """Prints summary statistics"""
    total = len(results)
    ok = sum(1 for r in results if r.status == ProxyStatus.OK)
    tls_freeze = sum(1 for r in results if r.status == ProxyStatus.TLS_FREEZE)
    timeout = sum(1 for r in results if r.status == ProxyStatus.TIMEOUT)
    errors = sum(1 for r in results if r.status in (ProxyStatus.ERROR, ProxyStatus.AUTH_FAILED))

    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"  Total checked: {total}")
    print(f"  \033[92mWorking (OK):       {ok}\033[0m")
    print(f"  \033[91mTLS Freeze (censor): {tls_freeze}\033[0m")
    print(f"  \033[91mTimeout:            {timeout}\033[0m")
    print(f"  \033[91mErrors:             {errors}\033[0m")
    print("=" * 50)


def save_working_proxies(results: list[ProxyResult], output_file: str) -> None:
    """Saves working proxies to file"""
    working = [r for r in results if r.status == ProxyStatus.OK]

    with open(output_file, 'w', encoding='utf-8') as f:
        for result in working:
            f.write(f"{result.proxy}\n")

    print(f"\nWorking proxies saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Proxy Checker - checks proxy functionality with TLS freeze (censorship) detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python proxy_checker.py proxy-list.txt
  python proxy_checker.py proxy-list.txt -c 10 -v
  python proxy_checker.py proxy-list.txt --timeout 60

TLS Freeze Detection:
  Detects censorship by identifying connections that stall after ~16-20KB
  of TLS traffic - a characteristic pattern of DPI-based blocking.
        """
    )

    parser.add_argument(
        "input_file",
        help="File with proxy list (format: host:port:username:password)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for working proxies",
        default=None
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent checks (default: 5)"
    )
    parser.add_argument(
        "--timeout-connect",
        type=float,
        default=10.0,
        help="Connection timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Total timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Load proxies
    proxies = load_proxies(args.input_file)
    if not proxies:
        print("No proxies to check")
        sys.exit(1)

    print(f"Loaded {len(proxies)} proxies for checking")
    print(f"Parameters: concurrency={args.concurrency}, timeout={args.timeout}s")
    print(f"TLS freeze detection: stall at {FREEZE_MIN_BYTES//1024}-{FREEZE_MAX_BYTES//1024}KB after {FREEZE_STALL_TIMEOUT}s")
    print("-" * 50)

    # Check proxies
    results = asyncio.run(check_proxies(
        proxies,
        concurrency=args.concurrency,
        timeout_connect=args.timeout_connect,
        timeout_total=args.timeout,
        verbose=args.verbose
    ))

    # Summary
    print_summary(results)

    # Save results
    if args.output:
        save_working_proxies(results, args.output)


if __name__ == "__main__":
    main()
