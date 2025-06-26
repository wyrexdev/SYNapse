import asyncio
import aiohttp
from typing import List, Optional
from .models import ScanResult, PortStatus, Protocol, ScanConfig
from .protocols import http, tls, quic, os_fingerprint

class AsyncPortScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.proxy = config.proxy

    async def _create_connection(self, host: str, port: int):
        if self.proxy:
            if self.proxy.startswith('http'):
                connector = aiohttp.TCPConnector()
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(f"http://{host}:{port}", proxy=self.proxy) as resp:
                        return resp
            else:
                from aiosocks import Socks5Auth, Socks5Connector
                auth = Socks5Auth(login='user', password='pass') 
                connector = Socks5Connector(proxy=self.proxy, proxy_auth=auth)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(f"http://{host}:{port}") as resp:
                        return resp
        else:
            return await asyncio.open_connection(host, port)

    async def _check_port(self, target: str, port: int) -> bool:
        try:
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)
                
            conn = self._create_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.config.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def _scan_port(self, target: str, port: int) -> ScanResult:
        async with self.semaphore:
            if self.config.resolve_dns and not target.replace('.', '').isdigit():
                target = await resolve_domain(target)
                
            is_open = await self._check_port(target, port)
            
            if not is_open:
                return ScanResult(
                    target=target,
                    port=port,
                    status=PortStatus.CLOSED,
                    protocol=Protocol.TCP
                )

            result = ScanResult(
                target=target,
                port=port,
                status=PortStatus.OPEN,
                protocol=Protocol.TCP,
                timestamp=asyncio.get_event_loop().time()
            )

            if self.config.banner_grab:
                result.banner = await http.grab_banner(target, port, self.config.timeout)

            if self.config.tls_scan and port in [443, 8443, 993, 995]:
                result.tls_info = await tls.scan_tls(target, port, self.config.timeout)

            if self.config.quic_scan and port in [443, 80]:
                result.quic_info = await quic.scan_quic(target, port, self.config.timeout)

            if self.config.os_fingerprinting:
                result.os_guess = await os_fingerprint.passive_os_fingerprint(target, port)

            return result

    async def scan(self, targets: List[str], ports: List[int]) -> List[ScanResult]:
        tasks = []
        for target in targets:
            for port in ports:
                tasks.append(self._scan_port(target, port))
        
        results = await asyncio.gather(*tasks)
        return [r for r in results if r.status == PortStatus.OPEN]