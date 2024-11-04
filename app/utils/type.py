
from enum import Enum
from datetime import datetime, timezone

# Scan method for a particular scan process
class ScanType(Enum):
    SCAN_BY_DOMAIN = 0
    SCAN_BY_IP = 1
    SCAN_BY_CT = 2

# Status of a particular scan process
class ScanStatusType(Enum):
    RUNNING = 0
    BACKEND_ERROR = 1
    COMPLETED = 2
    SUSPEND = 3
    KILLED = 4

# Identifiers for X509 cert type based on its position in the cert chain
class CertType(Enum):
    LEAF = 0
    INTERMEDIATE = 1
    ROOT = 2

# Identifiers for x509 leaf cert basd on its policies
class LeafCertType(Enum):
    DV = 0
    IV = 1
    OV = 2
    EV = 3

# User submitted task type
class TaskType(Enum):
    TASK_SCAN = 0
    TASK_ANALYSIS = 1
    TASK_WRITE_SQL = 2
    TASK_READ_SQL = 3

def sort_dict_by_key(dict):
    return {k: dict[k] for k in sorted(dict.keys())}

def sort_dict_by_value(dict):
    return {k: dict[k] for k in sorted(dict.values())}

def sort_list_by_key(data_list, key_name):
    return sorted(data_list, key=lambda x: x[key_name])

def date_time_to_timestamp(date_time : datetime):
    return int(date_time.timestamp() * 1000)  # 如果需要毫秒级时间戳，乘以1000

def str_to_timestamp(date_str):
    # format should be something like'2022-01-01 00:00:00', utc time
    dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    return date_time_to_timestamp(dt)

def timestamp_to_datetime(timestamp):
    # timestamp in microseconds
    timestamp_seconds = timestamp / 1000
    return datetime.fromtimestamp(timestamp_seconds)

def timestamp_to_str(timestamp):
    dt = timestamp_to_datetime(timestamp)
    return dt.strftime('%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
