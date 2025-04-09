
import sys
sys.path.append(r"D:\global_ca_monitor")

import time
from backend import app
from backend.config.scan_config import DomainScanConfig
from backend.utils.type import ScanType
from backend.celery import g_manager
from backend.celery.task import TaskBatchTemplate

with app.app_context():
    scan_type = ScanType(ScanType.SCAN_BY_INPUT)
    scan_args = {
        'MAX_THREADS_ALLOC' : 1000,
        'THREAD_WORKLOAD' : 2,
        'INPUT_DOMAIN_LIST_FILE' : "top10milliondomains.csv",
        'SCAN_PROCESS_NAME': "test 1-5M domain",
        'STORAGE_DIR' : "out",
        'SCAN_TIMEOUT' : 2,
        'MAX_RETRY' : 2,
        'DOMAIN_INDEX_START': 1000000,
        'NUM_DOMAIN_SCAN' : 5000000
    }

    config = DomainScanConfig(**scan_args)
    task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
    g_manager.start_submitted_tasks()

    while True:
        time.sleep(1)
