import asyncio
import ssl
from typing import Optional, Dict, Any
from datetime import datetime

async def scan_tls(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        conn = asyncio.open_connection(host, port, ssl=context)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        ssl_object = writer.transport.get_extra_info('ssl_object')
        
        tls_info = {
            'version': ssl_object.version(),
            'cipher': ssl_object.cipher(),
            'compression': ssl_object.compression(),
            'certificate': get_cert_info(ssl_object),
            'alpn_protocol': ssl_object.selected_alpn_protocol(),
            'session_reused': ssl_object.session_reused,
        }
        
        writer.close()
        await writer.wait_closed()
        
        return tls_info
    except Exception as e:
        return None

def get_cert_info(ssl_object) -> Dict[str, Any]:
    cert = ssl_object.getpeercert()
    if not cert:
        return None
        
    return {
        'subject': dict(x[0] for x in cert['subject']),
        'issuer': dict(x[0] for x in cert['issuer']),
        'version': cert.get('version'),
        'serialNumber': cert.get('serialNumber'),
        'notBefore': cert.get('notBefore'),
        'notAfter': cert.get('notAfter'),
        'extensions': cert.get('extensions', []),
    }