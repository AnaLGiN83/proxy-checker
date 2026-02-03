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
    SLOW = "SLOW (possible censorship)"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    AUTH_FAILED = "AUTH_FAILED"


@dataclass
class ProxyResult:
    proxy: str
    status: ProxyStatus
    response_time: Optional[float] = None
    download_speed: Optional[float] = None  # KB/s
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


async def check_proxy(
    proxy: ProxyConfig,
    timeout_connect: float = 10.0,
    timeout_total: float = 30.0,
    slow_threshold_time: float = 15.0,
    slow_threshold_speed: float = 10.0,  # KB/s - below this is considered slow
) -> ProxyResult:
    """
    Checks proxy for functionality and speed.
    
    Censorship/throttling detection criteria:
    - Response time > slow_threshold_time seconds
    - Download speed < slow_threshold_speed KB/s
    """
    test_urls = [
        ("https://httpbin.org/ip", "origin"),  # Returns IP
        ("https://api.ipify.org?format=json", "ip"),  # Alternative service
    ]

    # Speed test - using multiple URLs for reliability
    speed_test_urls = [
        "https://www.google.com/",  # ~15KB
        "https://httpbin.org/bytes/51200",  # 50KB
    ]

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
                        ssl=False
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

            # Test 2: Download speed check
            download_speed = None
            
            for speed_url in speed_test_urls:
                speed_start = time.perf_counter()
                downloaded_bytes = 0
                
                try:
                    async with session.get(
                        speed_url,
                        proxy=proxy.url,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=20)
                    ) as response:
                        if response.status == 200:
                            async for chunk in response.content.iter_chunked(8192):
                                downloaded_bytes += len(chunk)
                            
                            speed_time = time.perf_counter() - speed_start
                            if speed_time > 0 and downloaded_bytes > 0:
                                download_speed = (downloaded_bytes / 1024) / speed_time
                                break  # Success, exit loop
                except asyncio.TimeoutError:
                    continue  # Try next URL
                except Exception:
                    continue

            # Determine status
            total_time = time.perf_counter() - start_time

            # Proxy is considered slow if:
            # 1. Total time > threshold AND speed is measured and low
            # 2. OR speed is measured and very low (< threshold)
            is_slow = False
            if download_speed is not None:
                if download_speed < slow_threshold_speed:
                    is_slow = True
            if total_time > slow_threshold_time:
                is_slow = True

            status = ProxyStatus.SLOW if is_slow else ProxyStatus.OK

            return ProxyResult(
                proxy=str(proxy),
                status=status,
                response_time=response_time,
                download_speed=download_speed,
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
        ProxyStatus.OK: "\033[92m",       # Green
        ProxyStatus.SLOW: "\033[93m",     # Yellow
        ProxyStatus.TIMEOUT: "\033[91m",  # Red
        ProxyStatus.ERROR: "\033[91m",    # Red
        ProxyStatus.AUTH_FAILED: "\033[91m"  # Red
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
        if result.download_speed is not None:
            print(f"  └─ Download speed: {result.download_speed:.1f} KB/s")
        if result.error_message:
            print(f"  └─ Error: {result.error_message}")


async def check_proxies(
    proxies: list[ProxyConfig],
    concurrency: int = 5,
    timeout_connect: float = 10.0,
    timeout_total: float = 30.0,
    slow_threshold_time: float = 15.0,
    slow_threshold_speed: float = 50.0,
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
                slow_threshold_time=slow_threshold_time,
                slow_threshold_speed=slow_threshold_speed
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
    slow = sum(1 for r in results if r.status == ProxyStatus.SLOW)
    timeout = sum(1 for r in results if r.status == ProxyStatus.TIMEOUT)
    errors = sum(1 for r in results if r.status in (ProxyStatus.ERROR, ProxyStatus.AUTH_FAILED))

    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"  Total checked: {total}")
    print(f"  \033[92mWorking (OK):    {ok}\033[0m")
    print(f"  \033[93mSlow (SLOW):     {slow}\033[0m")
    print(f"  \033[91mTimeout:         {timeout}\033[0m")
    print(f"  \033[91mErrors:          {errors}\033[0m")
    print("=" * 50)


def save_working_proxies(results: list[ProxyResult], output_file: str, include_slow: bool = False) -> None:
    """Saves working proxies to file"""
    working = [r for r in results if r.status == ProxyStatus.OK]
    if include_slow:
        working.extend([r for r in results if r.status == ProxyStatus.SLOW])

    with open(output_file, 'w', encoding='utf-8') as f:
        for result in working:
            f.write(f"{result.proxy}\n")

    print(f"\nWorking proxies saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Proxy Checker - checks proxy functionality with censorship detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python proxy_checker.py proxy-list.txt
  python proxy_checker.py proxy-list.txt -c 10 -v
  python proxy_checker.py proxy-list.txt --timeout 60 --slow-time 20
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
        "--slow-time",
        type=float,
        default=15.0,
        help="Time threshold for slow proxy detection in seconds (default: 15)"
    )
    parser.add_argument(
        "--slow-speed",
        type=float,
        default=50.0,
        help="Speed threshold for slow proxy detection in KB/s (default: 50)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--include-slow",
        action="store_true",
        help="Include slow proxies in working list when saving"
    )

    args = parser.parse_args()

    # Load proxies
    proxies = load_proxies(args.input_file)
    if not proxies:
        print("No proxies to check")
        sys.exit(1)

    print(f"Loaded {len(proxies)} proxies for checking")
    print(f"Parameters: concurrency={args.concurrency}, timeout={args.timeout}s")
    print(f"Censorship thresholds: time>{args.slow_time}s or speed<{args.slow_speed}KB/s")
    print("-" * 50)

    # Check proxies
    results = asyncio.run(check_proxies(
        proxies,
        concurrency=args.concurrency,
        timeout_connect=args.timeout_connect,
        timeout_total=args.timeout,
        slow_threshold_time=args.slow_time,
        slow_threshold_speed=args.slow_speed,
        verbose=args.verbose
    ))

    # Summary
    print_summary(results)

    # Save results
    if args.output:
        save_working_proxies(results, args.output, args.include_slow)


if __name__ == "__main__":
    main()
