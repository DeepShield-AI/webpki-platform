
from backend.config.scan_config import CTScanConfig
from backend.scanner.celery_scan_task import request_ct_log
from pprint import pprint

test_config = CTScanConfig(
    scan_task_name="yeti2025 test",
    output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/ca_certs",
    proxy_host=None,
    proxy_port=None,
    scan_timeout=2,
    max_retry=10,
    ct_log_name="yeti2025",
    ct_log_address="yeti2025.ct.digicert.com/log",
    entry_start=0,
    entry_end=100,
    window_size=20
)

entry_start = 0
entry_end = 100
window_size = 20
for i in range(entry_start, entry_end, window_size):
    ct_result = request_ct_log(i, i + window_size, test_config)
    pprint(ct_result)
