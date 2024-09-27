
import os
from flask import Request
from ..utils.type import ScanType


class ScanConfig:
    def __init__(self, **kwargs):
        # name of scan process
        self.SCAN_PROCESS_NAME = kwargs.get('SCAN_PROCESS_NAME', '')
        # scan data output directory (raw data)
        self.STORAGE_DIR = kwargs.get('STORAGE_DIR', os.path.join(os.path.dirname(__file__), r"../data/raw_cert_data/ct_scan"))
        # scan concurrency level
        self.MAX_THREADS_ALLOC = kwargs.get('MAX_THREADS_ALLOC', 100)
        self.THREAD_WORKLOAD = kwargs.get('THREAD_WORKLOAD', 2000)
        # proxy settings (if applicable)
        self.PROXY_HOST = kwargs.get('PROXY_HOST', '127.0.0.1')
        self.PROXY_PORT = kwargs.get('PROXY_PORT', 33210)
        # retry settings
        self.SCAN_TIMEOUT = kwargs.get('SCAN_TIMEOUT', 5)
        self.MAX_RETRY = kwargs.get('MAX_RETRY', 3)


class DomainScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # domain list file related
        self.INPUT_DOMAIN_LIST_FILE = kwargs.get('INPUT_DOMAIN_LIST_FILE', os.path.join(os.path.dirname(__file__), r"../data/top-1m.csv"))
        self.DOMAIN_RANK_START = kwargs.get('DOMAIN_RANK_START', 0)
        self.NUM_DOMAIN_SCAN = kwargs.get('NUM_DOMAIN_SCAN', 100)
        self.SCAN_PORT = kwargs.get('SCAN_PORT', 443)
        # TLS fingerprinting config
        self.TLS_FP_TYPE = kwargs.get('TLS_FP_TYPE', "jarm")


class IPScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # IP range file related
        self.INPUT_IP_LIST_FILE = kwargs.get('INPUT_IP_LIST_FILE', "")
        self.SCAN_PORT = kwargs.get('SCAN_PORT', 443)
        # TLS fingerprinting config
        self.TLS_FP_TYPE = kwargs.get('TLS_FP_TYPE', "jarm")


class CTScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # CT log request url construction
        self.CT_LOG_NAME = kwargs.get('CT_LOG_NAME', "")
        self.CT_LOG_ADDRESS = kwargs.get('CT_LOG_ADDRESS', "")
        self.ENTRY_START = kwargs.get('ENTRY_START', 0)
        self.ENTRY_END = kwargs.get('ENTRY_END', 1000)
        self.WINDOW_SIZE = kwargs.get('WINDOW_SIZE', 10)


class DNSScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # need NS and record types
        self.NS = kwargs.get('NS', ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        self.RECORD_TYPES = kwargs.get("RECORD_TYPES", ["A", "AAAA", "TXT"])


config_class_mapping = {
    ScanType.SCAN_BY_DOMAIN: DomainScanConfig,
    ScanType.SCAN_BY_IP: IPScanConfig,
    ScanType.SCAN_BY_CT: CTScanConfig,
}

def create_scan_config_from_frontend_request(request : Request, scan_type : ScanType):

    common_args = {
        'SCAN_PROCESS_NAME': request.json.get('scan_process_name'),
        'STORAGE_DIR' : request.json.get('storage_dir'),
        'MAX_THREADS_ALLOC': int(request.json.get('max_threads_alloc')),
        'THREAD_WORKLOAD' : int(request.json.get('thread_workload')),
        'SCAN_TIMEOUT': int(request.json.get('scan_timeout')),
        'MAX_RETRY': int(request.json.get('max_retry')),
    }

    if request.json.get('proxy_host'):
        common_args['PROXY_HOST'] = request.json.get('proxy_host')
    if request.json.get('proxy_port'):
        common_args['PROXY_PORT'] = request.json.get('proxy_port')

    if scan_type == ScanType.SCAN_BY_DOMAIN:
        if request.json.get('input_domain_list_file'):
            common_args['INPUT_DOMAIN_LIST_FILE'] = request.json.get('input_domain_list_file')
        if request.json.get('domain_rank_start'):
            common_args['DOMAIN_RANK_START'] = request.json.get('domain_rank_start')
        if request.json.get('num_domain_scan'):
            common_args['NUM_DOMAIN_SCAN'] = request.json.get('num_domain_scan')
        return DomainScanConfig(**common_args)

    if scan_type == ScanType.SCAN_BY_IP:
        if request.json.get('input_ip_list_file'):
            common_args['INPUT_IP_LIST_FILE'] = request.json.get('input_ip_list_file')
        return IPScanConfig(**common_args)

    if scan_type == ScanType.SCAN_BY_CT:
        if request.json.get('ct_log_name'):
            common_args['CT_LOG_NAME'] = request.json.get('ct_log_name')
        if request.json.get('ct_log_address'):
            common_args['CT_LOG_ADDRESS'] = request.json.get('ct_log_address')
        if request.json.get('entry_start'):
            common_args['ENTRY_START'] = request.json.get('entry_start')
        if request.json.get('entry_end'):
            common_args['ENTRY_END'] = request.json.get('entry_end')
        if request.json.get('window_size'):
            common_args['WINDOW_SIZE'] = request.json.get('window_size')
        return CTScanConfig(**common_args)

