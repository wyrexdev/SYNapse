from typing import List
from .models import ScanResult

def format_results(results: List[ScanResult], verbose: bool = False) -> str:
    output = []
    
    for result in results:
        line = f"[+] {result.target}:{result.port} {result.status.value.upper()}"
        
        if result.banner:
            line += f" | Banner: {result.banner[:100]}"
            
        if result.tls_info and verbose:
            line += f"\n   TLS: {result.tls_info.get('version')} {result.tls_info.get('cipher')}"
            if result.tls_info.get('certificate'):
                line += f"\n   Cert Subject: {result.tls_info['certificate']['subject']}"
                
        if result.quic_info and verbose:
            line += f"\n   QUIC: {'Supported' if result.quic_info.get('supported') else 'Not supported'}"
            
        output.append(line)
    
    return "\n".join(output)