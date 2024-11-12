
import sys
sys.path.append(r"/root/global_ca_monitor")

from app import app
from app.config.scan_config import CTScanConfig
from app.utils.type import ScanType
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate

log_address = "oak.ct.letsencrypt.org/2024h1"
header_request = f"https://{log_address}/ct/v1/get-sth"

if __name__ == "__main__":
    with app.app_context():
        scan_type = ScanType(ScanType.SCAN_BY_CT)
        scan_args = {
            'SCAN_PROCESS_NAME': "oak 2024h1 test",
            'CT_LOG_ADDRESS' : log_address,
            'WINDOW_SIZE' : 20
        }

        config = CTScanConfig(**scan_args)
        task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
        g_manager.start_submitted_tasks()
