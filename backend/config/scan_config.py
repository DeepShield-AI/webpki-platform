
import os
from dataclasses import dataclass, asdict, fields, field
from typing import List, Type, TypeVar, Any

from flask import Request
from backend.utils.type import ScanType

from backend.config.config_loader import (
    MAX_THREADS_ALLOC, THREAD_WORKLOAD, SCAN_TIMEOUT, MAX_RETRY,
    DEFAULT_DOMAIN_LIST_FILE, DEFAULT_IP_LIST_FILE, DEFAULT_STORAGE_DIR
)

# define a template type variable, can be any type
T = TypeVar("T")

def from_dict(cls: Type[T], data: dict) -> T:
    field_names = {f.name for f in fields(cls)}
    init_data = {k: v for k, v in data.items() if k in field_names}
    return cls(**init_data)

@dataclass
class ScanConfig:
    scan_process_name: str = ""
    storage_dir: str = DEFAULT_STORAGE_DIR
    max_threads_alloc: int = MAX_THREADS_ALLOC
    thread_workload: int = THREAD_WORKLOAD
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 33210
    scan_timeout: int = SCAN_TIMEOUT
    max_retry: int = MAX_RETRY

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[T], data: dict) -> T:
        return from_dict(cls, data)


@dataclass
class DomainScanConfig(ScanConfig):
    scan_tool: str = "zgrab2"
    input_domain_list_file: str = DEFAULT_DOMAIN_LIST_FILE
    domain_index_start: int = 0
    num_domain_scan: int = 100
    scan_port: int = 443
    tls_fp_type: str = "jarm"
    tls_fp_only: bool = True


@dataclass
class IPScanConfig(ScanConfig):
    scan_tool: str = "zmap + zgrab2"
    input_ip_list_file: str = DEFAULT_IP_LIST_FILE
    scan_port: int = 443
    tls_fp_type: str = "jarm"
    tls_fp_only: bool = True


@dataclass
class CTScanConfig(ScanConfig):
    ct_log_name: str = ""
    ct_log_address: str = ""
    entry_start: int = 0
    entry_end: int = 1000
    window_size: int = 10


# field(default_factory=...) 是 dataclasses 中的语法，用来设置可变类型（如 list、dict）的默认值。不能写成：
# ns: List[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # 会导致所有实例共享同一个列表对象
@dataclass
class DNSScanConfig(ScanConfig):
    ns: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    record_types: List[str] = field(default_factory=lambda: ["A", "AAAA", "TXT"])


def create_scan_config_from_frontend_request(request: Request, scan_type: ScanType) -> ScanConfig:
    common_args = {
        'scan_process_name': request.json.get('scan_process_name'),
        'storage_dir': request.json.get('storage_dir'),
        'max_threads_alloc': int(request.json.get('max_threads_alloc')),
        'thread_workload': int(request.json.get('thread_workload')),
        'scan_timeout': int(request.json.get('scan_timeout')),
        'max_retry': int(request.json.get('max_retry')),
        'proxy_host': request.json.get('proxy_host', '127.0.0.1'),
        'proxy_port': int(request.json.get('proxy_port', 33210)),
    }

    if scan_type == ScanType.SCAN_BY_DOMAIN:
        return DomainScanConfig(
            **common_args,
            input_domain_list_file=request.json.get('input_domain_list_file'),
            domain_index_start=int(request.json.get('domain_index_start', 0)),
            num_domain_scan=int(request.json.get('num_domain_scan', 100)),
        )
    elif scan_type == ScanType.SCAN_BY_IP:
        return IPScanConfig(
            **common_args,
            input_ip_list_file=request.json.get('input_ip_list_file')
        )
    elif scan_type == ScanType.SCAN_BY_CT:
        return CTScanConfig(
            **common_args,
            ct_log_name=request.json.get('ct_log_name'),
            ct_log_address=request.json.get('ct_log_address'),
            entry_start=int(request.json.get('entry_start', 0)),
            entry_end=int(request.json.get('entry_end', 1000)),
            window_size=int(request.json.get('window_size', 10)),
        )
    else:
        raise ValueError(f"Unsupported scan_type: {scan_type}")
