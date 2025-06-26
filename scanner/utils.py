import asyncio
import ipaddress
import re
import socket
from typing import List, Union

def parse_targets(target_input: str) -> List[str]:
    targets = []
    
    if '-' in target_input and re.match(r'^\d+\.\d+\.\d+\.\d+-\d+$', target_input):
        base_ip, end = target_input.split('-')
        base_parts = base_ip.split('.')
        start = int(base_parts[3])
        
        for i in range(start, int(end) + 1):
            targets.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
    
    elif '/' in target_input:
        network = ipaddress.ip_network(target_input, strict=False)
        targets.extend(str(host) for host in network.hosts())
    
    else:
        targets.append(target_input)
    
    return targets

async def resolve_domain(domain: str) -> str:
    try:
        return (await asyncio.get_event_loop().getaddrinfo(
            domain, None, proto=socket.IPPROTO_TCP
        ))[0][4][0]
    except socket.gaierror:
        return domain

def parse_ports(port_input: str, excluded: List[int] = None) -> List[int]:
    excluded = excluded or []
    ports = []
    
    if ',' in port_input:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(p for p in range(start, end + 1) if p not in excluded)
            else:
                port = int(part)
                if port not in excluded:
                    ports.append(port)
    elif '-' in port_input:
        start, end = map(int, port_input.split('-'))
        ports.extend(p for p in range(start, end + 1) if p not in excluded)
    else:
        port = int(port_input)
        if port not in excluded:
            ports.append(port)
    
    return ports