import argparse
import asyncio
import json
from datetime import datetime
from typing import List, TextIO
from scanner.core import AsyncPortScanner
from scanner.models import ScanConfig
from scanner.utils import parse_targets, parse_ports
from scanner.output import format_results
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
import socket
import time

async def enhanced_scan_quic(host: str, port: int, timeout: float) -> dict:
    result = {
        'supported': False,
        'version': None,
        'alpn': None,
        'handshake_time': None,
        'ciphers': None,
        'error': None
    }

    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=False 
    )

    try:
        start_time = time.time()
        
        async with connect(
            host=host,
            port=port,
            configuration=configuration,
            timeout=timeout
        ) as protocol:
            await protocol.wait_handshake()
            handshake_time = time.time() - start_time

            result.update({
                'supported': True,
                'version': protocol._quic.version,
                'alpn': protocol._quic.alpn_negotiated,
                'handshake_time': round(handshake_time, 4),
                'ciphers': protocol._quic.tls.cipher_suite.name if protocol._quic.tls else None
            })

    except ConnectionRefusedError:
        result['error'] = 'connection_refused'
    except asyncio.TimeoutError:
        result['error'] = 'timeout'
    except socket.gaierror:
        result['error'] = 'dns_resolution_failed'
    except Exception as e:
        result['error'] = str(e)

    return result

def save_results(results: List[dict], output_file: TextIO, format: str = 'text'):
    if format == 'json':
        json.dump([r.__dict__ for r in results], output_file, indent=2)
    else:
        output_file.write(format_results(results, verbose=True))

def main():
    parser = argparse.ArgumentParser(description="⚡ SYNapse Async Port Scanner")
    
    parser.add_argument('targets', help='Target(s) to scan (IP, IP range, or domain)')
    parser.add_argument('-p', '--ports', required=True, help='Port(s) to scan (e.g., 80 or 20-100)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds')
    parser.add_argument('-c', '--concurrency', type=int, default=500, help='Maximum concurrent connections')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed output')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between connections in seconds')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'), help='Save results to file')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner grabbing')
    parser.add_argument('--tls', action='store_true', help='Enable TLS scanning')
    parser.add_argument('--quic', action='store_true', help='Enable QUIC detection (enhanced)')
    parser.add_argument('--resolve', action='store_true', help='Resolve domains to IPs')
    parser.add_argument('--os-guess', action='store_true', help='Enable OS fingerprinting')
    parser.add_argument('--exclude-ports', help='Comma-separated list of ports to exclude')
    parser.add_argument('--proxy', help='Proxy server (http/socks5://host:port)')
    
    args = parser.parse_args()
    
    excluded_ports = []
    if args.exclude_ports:
        excluded_ports = [int(p) for p in args.exclude_ports.split(',')]
    
    config = ScanConfig(
        timeout=args.timeout,
        concurrency=args.concurrency,
        banner_grab=not args.no_banner,
        tls_scan=args.tls,
        quic_scan=args.quic,
        resolve_dns=args.resolve,
        delay=args.delay,
        proxy=args.proxy,
        excluded_ports=excluded_ports,
        os_fingerprinting=args.os_guess
    )
    
    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports, excluded_ports)
    
    print(f"🚀 Starting scan: {len(targets)} target(s), {len(ports)} port(s)")
    if args.quic:
        print(f"🔍 QUIC Scanning: Enhanced protocol detection enabled")
    print(f"⚡ Concurrency: {config.concurrency} | Timeout: {config.timeout}s")
    print(f"🔧 Options: Delay={config.delay}s | Proxy={config.proxy or 'None'}")
    print("─" * 50)
    
    start_time = datetime.now()
    
    try:
        scanner = AsyncPortScanner(config)
        results = asyncio.run(scanner.scan(targets, ports))
        
        print(format_results(results, args.verbose))
        
        if args.output:
            save_results(results, args.output, 'json' if args.json else 'text')
            print(f"\n💾 Results saved to {args.output.name}")
        
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error during scan: {str(e)}")
    finally:
        print("─" * 50)
        print(f"✅ Scan completed in {datetime.now() - start_time}")
        print(f"📊 Results: {len(results)} open ports found")

if __name__ == '__main__':
    main()