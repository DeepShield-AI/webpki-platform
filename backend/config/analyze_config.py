
from dataclasses import dataclass, field

@dataclass
class AnalyzeConfig:
    # Task flag constants (bitwise OR for multiple subtasks)
    TASK_CERT_FP: int = field(init=False, default=0b0001)  # for parsing certificates
    TASK_CHAIN: int = field(init=False, default=0b0010)  # for building chains
    TASK_REVOKE: int = field(init=False, default=0b0100) # for checking revocation

    TASK_CAG: int = field(init=False, default=0b1000) # for building CAG for certain webpages

    # the output_dir if applies
    out_dir: str = r"out"

    # cert_table determines which certificate table to analyze.
    cert_table: str = "cert"

    # task_flag controls which subtasks to run.
    # combine the subtask flags above using bitwise OR.
    task_flag: int = 0b0001

    # single_task_workload sets how many certificates each task should handle.
    single_task_workload: int = 2000

    # max_tasks_parallel limits the maximum number of concurrent tasks.
    max_tasks_parallel: int = 100


# @deprecated
class CaAnalysisConfig:

    PARSE_SUBTASK = 0b0001
    CLUSTERING_SUBTASK = 0b0010

    def __init__(self, **kwargs):

        self.SCAN_ID  = kwargs.get('SCAN_ID', None)
        self.SUBTASK_FLAG = kwargs.get('SUBTASK_FLAG', 0b0001)
        self.THREAD_WORKLOAD = kwargs.get('THREAD_WORKLOAD', 2000)
        self.MAX_THREADS_ALLOC = kwargs.get('MAX_THREADS_ALLOC', 100)


# def create_analyze_config(request : Request, analyze_type : int):

#     common_args = {
#         'SCAN_ID': request.json.get('scanId'),
#         'SUBTASK_FLAG': int(request.json.get('flag')),
#         'THREAD_WORKLOAD': int(request.json.get('saveChunkSize')),
#         'MAX_THREADS_ALLOC': int(request.json.get('scanThreadNum')),
#     }

#     if analyze_type == 0:
#         return AnalyzeConfig(**common_args)
#     else:
#         return None

# ZLINT_PATH = r"/root/zlint/v3/zlint"
# TRUST_ROOT_DIR = r"/root/pki-internet-platform/data/trust_roots"
# CA_CERT_DIR = r"/data/ct_log_data"

# IP2LOCATIONDB1_DIR = r"/data/ip2location/db1/IP2LOCATION-LITE-DB1.BIN"
# IP2LOCATIONDB3_DIR = r"/data/ip2location/db3/IP2LOCATION-LITE-DB3.BIN"
# IP2LOCATIONASN_DIR = r"/data/ip2location/asn/IP2LOCATION-LITE-ASN.BIN"
