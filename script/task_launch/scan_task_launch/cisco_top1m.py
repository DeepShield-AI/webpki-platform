
# scan for top-10k domains

from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = InputScanConfig(
        "CiscoTop1m 20250626",
        proxy_host=None,
        proxy_port=None,
        input_list_file=r"/root/pki-internet-platform/data/top_domains/cisco-top-1m-new.csv",
    )

    launch_scan_task.delay(test_config.to_dict())
