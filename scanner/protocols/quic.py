import asyncio
from typing import Optional, Dict, Any
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
import socket
import time

async def scan_quic(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    result = {
        'supported': False,
        'version': None,
        'alpn': None,
        'handshake_time': None,
        'error': None
    }

    if port is None:
        port = 443

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
            create_protocol=QuicScanProtocol,
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

class QuicScanProtocol(asyncio.Protocol):
    def __init__(self):
        self._handshake_complete = asyncio.Event()

    async def wait_handshake(self):
        await self._handshake_complete.wait()

    def quic_event_received(self, event: QuicEvent):
        if hasattr(event, 'handshake_completed') and event.handshake_completed:
            self._handshake_complete.set()