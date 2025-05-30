
# scan_config
from typing import List, Type, TypeVar, Any
from dataclasses import dataclass, asdict, fields, field
from backend.config.config_loader import (
    MAX_TASKS_PARALLEL, SINGLE_TASK_WORKLOAD, SCAN_TIMEOUT, MAX_RETRY, ENABLE_JARM,
    INPUT_LIST_FILE, OUTPUT_DIR,
    PROXY_HOST, PROXY_PORT,
    RECURSIVE_DEPTH
)

# define a template type variable, can be any type
T = TypeVar("T")

def from_dict(cls: Type[T], data: dict) -> T:
    field_names = {f.name for f in fields(cls)}
    init_data = {k: v for k, v in data.items() if k in field_names}
    return cls(**init_data)

@dataclass
class ScanConfig:
    scan_task_name: str = ""
    output_file_dir: str = OUTPUT_DIR
    max_tasks_parallel: int = MAX_TASKS_PARALLEL
    single_task_workload: int = SINGLE_TASK_WORKLOAD
    proxy_host: str = PROXY_HOST
    proxy_port: int = PROXY_PORT
    scan_timeout: int = SCAN_TIMEOUT
    max_retry: int = MAX_RETRY

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[T], data: dict) -> T:
        return from_dict(cls, data)

@dataclass
class InputScanConfig(ScanConfig):
    input_list_file: str = INPUT_LIST_FILE
    enable_jarm: bool = ENABLE_JARM
    scan_port: int = 443

    # this is for recursive scanning in web page
    recursive_depth : int = RECURSIVE_DEPTH

    # this is for reverse DNS option
    reverse_dns: bool = False

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

