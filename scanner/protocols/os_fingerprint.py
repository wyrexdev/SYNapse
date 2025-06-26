import socket
import asyncio
from typing import Dict, Any, Optional

async def passive_os_fingerprint(host: str, port: int) -> Optional[Dict[str, Any]]:
    try:
        reader, writer = await asyncio.open_connection(host, port)
        
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            except (OSError, AttributeError):
                ttl = None
            
            try:
                window_size = sock.getsockopt(socket.SOL_TCP, socket.TCP_WINDOW_CLAMP)
            except (OSError, AttributeError):
                window_size = None
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'ttl': ttl,
                'window_size': window_size,
            }
        return None
    except Exception:
        return None