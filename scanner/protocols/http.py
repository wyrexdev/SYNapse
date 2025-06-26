import asyncio
from typing import Optional

async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        
        writer.write(b'GET / HTTP/1.1\r\nHost: %b\r\n\r\n' % host.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        if not data:
            writer.write(b'\r\n')
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        writer.close()
        await writer.wait_closed()
        
        return data.decode(errors='ignore').strip()
    except:
        return None