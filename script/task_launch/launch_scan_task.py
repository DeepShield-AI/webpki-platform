
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate
from app.config.scan_config import DomainScanConfig, CTScanConfig

log_address = "oak.ct.letsencrypt.org/2024h2"

if __name__ == "__main__":
    with app.app_context():
        scan_args = {
            'SCAN_PROCESS_NAME': "oak 2024h2 1000-2000",
            'THREAD_WORKLOAD' : 100,
            'SCAN_TIMEOUT' : 2,
            'MAX_RETRY' : 5,
            'CT_LOG_ADDRESS' : log_address,
            'ENTRY_START' : 1000,
            'ENTRY_END' : 2000,
            'WINDOW_SIZE' : 10,
        }
        config = CTScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        # scan_args = {'SCAN_PROCESS_NAME': "test_scan_20240820"}
        # scan_task = TaskBatchTemplate.create_scan_task(DomainScanConfig(**scan_args))
        # g_manager.submit_task([scan_task])
        # g_manager.start_submitted_tasks()
