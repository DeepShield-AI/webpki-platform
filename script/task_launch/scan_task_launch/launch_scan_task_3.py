
import sys
sys.path.append(r"/root/pki-internet-platform")

import time
from backend import app, db
from backend.celery import g_manager
from backend.celery.task import TaskBatchTemplate
from backend.config.scan_config import DomainScanConfig, CTScanConfig

log_name = "oak2024h2"
log_address = "oak.ct.letsencrypt.org/2024h2"
# log_name = "sabre2024h2"
# log_address = "sabre2024h2.ct.sectigo.com"
# log_address = "yeti2024.ct.digicert.com/log"
# log_address = "ct.cloudflare.com/logs/nimbus2024"
# log_name = "nimbus2024"
# log_name = "yeti2024"
# 188918416

if __name__ == "__main__":
    with app.app_context():
        scan_args = {
            'SCAN_PROCESS_NAME': "oak2024h2 0-150M",
            'STORAGE_DIR' : r"/data/ct_log_data/oak2024h2",
            'MAX_THREADS_ALLOC' : 100,
            'THREAD_WORKLOAD' : 10000,
            'SCAN_TIMEOUT' : 5,
            'MAX_RETRY' : 10,
            'CT_LOG_NAME' : log_name,
            'CT_LOG_ADDRESS' : log_address,
            'ENTRY_START' : 0,
            'ENTRY_END' : 150000000,
            'WINDOW_SIZE' : 250,
        }
        config = CTScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()

        while True:
            time.sleep(1)
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
    # https://nessie2022.ct.digicert.com/log
    # https://nessie2023.ct.digicert.com/log
	# https://nessie2024.ct.digicert.com/log
    # https://nessie2025.ct.digicert.com/log
	# https://ct.cloudflare.com/logs/nimbus2024
	# https://ct.cloudflare.com/logs/nimbus2025
