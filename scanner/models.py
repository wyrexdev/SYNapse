from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum

class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    QUIC = "quic"

@dataclass
class ScanResult:
    target: str
    port: int
    status: PortStatus
    protocol: Protocol
    banner: Optional[str] = None
    tls_info: Optional[Dict[str, Any]] = None
    quic_info: Optional[Dict[str, Any]] = None
    os_guess: Optional[Dict[str, Any]] = None
    response_time: Optional[float] = None
    service: Optional[str] = None
    timestamp: float = None

@dataclass
class ScanConfig:
    timeout: float = 1.0
    concurrency: int = 500
    banner_grab: bool = True
    tls_scan: bool = False
    quic_scan: bool = False
    service_detection: bool = False
    resolve_dns: bool = False
    delay: float = 0.0
    proxy: Optional[str] = None
    excluded_ports: List[int] = None
    os_fingerprinting: bool = False