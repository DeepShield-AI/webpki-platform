
import sys
sys.path.append(r"D:\global_ca_monitor")

from app import app, db
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate
from app.config.scan_config import DomainScanConfig, CTScanConfig

# log_address = "oak.ct.letsencrypt.org/2024h2"
# log_address = "sabre2025h2.ct.sectigo.com"
log_address = "yeti2023.ct.digicert.com/log"
log_name = "yeti2023"

if __name__ == "__main__":
    with app.app_context():
        scan_args = {
            'SCAN_PROCESS_NAME': "yeti2023 0-50M",
            'STORAGE_DIR' : r"H:/yeti2023",
            'MAX_THREADS_ALLOC' : 200,
            'THREAD_WORKLOAD' : 1000,
            'SCAN_TIMEOUT' : 2,
            'MAX_RETRY' : 10,
            'CT_LOG_NAME' : log_name,
            'CT_LOG_ADDRESS' : log_address,
            'ENTRY_START' : 0,
            'ENTRY_END' : 50000000,
            'WINDOW_SIZE' : 200,
        }
        config = CTScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        # scan_args = {'SCAN_PROCESS_NAME': "test_scan_20240820"}
        # scan_task = TaskBatchTemplate.create_scan_task(DomainScanConfig(**scan_args))
        # g_manager.submit_task([scan_task])
        # g_manager.start_submitted_tasks()

	# https://yeti2023.ct.digicert.com/log
	# https://yeti2024.ct.digicert.com/log
	# https://yeti2025.ct.digicert.com/log
	# https://sabre2024h1.ct.sectigo.com
    # https://sabre2024h2.ct.sectigo.com
	# https://sabre2025h1.ct.sectigo.com
	# https://sabre2025h2.ct.sectigo.com
