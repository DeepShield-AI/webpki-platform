
import sys
sys.path.append(r"/root/pki-internet-platform")

import time
from backend import app
from backend.config.scan_config import DomainScanConfig
from backend.utils.type import ScanType
from backend.celery import g_manager
from backend.celery.task import TaskBatchTemplate

if __name__ == "__main__":
    with app.app_context():
        scan_type = ScanType(ScanType.SCAN_BY_INPUT)
        scan_args = {
            'SCAN_TOOL' : "zgrab2",
            'MAX_THREADS_ALLOC' : 50,
            'THREAD_WORKLOAD' : 2,
            'INPUT_DOMAIN_LIST_FILE' : r"/root/pki-internet-platform/data/gov_domains/cn/cn_gov_20241106",
            'SCAN_PROCESS_NAME': "CN GOV 20250324",
            # 'STORAGE_DIR' : r"/data/self_scan_data/CN_GOV_20241203",
            'STORAGE_DIR' : r"/data/zgrab2_scan_data",
            'SCAN_TIMEOUT' : 10,
            'MAX_RETRY' : 10,
            'DOMAIN_INDEX_START': 0,
            'NUM_DOMAIN_SCAN' : 100000,
            'TLS_FP_TYPE' : "jarm",
            'TLS_FP_ONLY' : False
        }

        config = DomainScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        while True:
            time.sleep(1)
