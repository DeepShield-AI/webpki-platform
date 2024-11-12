
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import time
from app import app
from app.config.scan_config import DomainScanConfig
from app.utils.type import ScanType
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate

if __name__ == "__main__":
    with app.app_context():
        scan_type = ScanType(ScanType.SCAN_BY_DOMAIN)
        scan_args = {
            'SCAN_TOOL' : "zgrab2",
            'MAX_THREADS_ALLOC' : 1000,
            'THREAD_WORKLOAD' : 2,
            'INPUT_DOMAIN_LIST_FILE' : r"/root/pki-internet-platform/data/top_domains/cisco-top-1m.csv",
            'SCAN_PROCESS_NAME': "CiscoTop1M 20241110",
            'STORAGE_DIR' : r"/data/zgrab2_scan_data",
            'SCAN_TIMEOUT' : 10,
            'MAX_RETRY' : 10,
            'DOMAIN_INDEX_START': 0,
            'NUM_DOMAIN_SCAN' : 1000000,
            'TLS_FP_TYPE' : "jarm",
            'TLS_FP_ONLY' : True
        }

        config = DomainScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        while True:
            time.sleep(1)
