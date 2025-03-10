
import sys
sys.path.append(r"D:\global_ca_monitor")

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
            'MAX_THREADS_ALLOC' : 1000,
            'THREAD_WORKLOAD' : 2,
            'INPUT_DOMAIN_LIST_FILE' : os.path.join(os.path.dirname(__file__), r"../../data/domain_list/domain_list_nimbus"),
            'SCAN_PROCESS_NAME': "nimbus_associate_domain_list",
            'STORAGE_DIR' : "out",
            'SCAN_TIMEOUT' : 2,
            'MAX_RETRY' : 2,
            'DOMAIN_INDEX_START': 0,
            'NUM_DOMAIN_SCAN' : 120389,
            'TLS_FP_TYPE' : "jarm",
            'TLS_FP_ONLY' : True
        }

        config = DomainScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        while True:
            time.sleep(1)
