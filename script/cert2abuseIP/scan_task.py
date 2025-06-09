
# For Abuse IP DB Scan

from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = InputScanConfig(
        "AbuseIPDB Blacklist 20250609 1-2k",
        proxy_host=None,
        proxy_port=None,
        input_list_file=r"/root/pki-internet-platform/script/cert2abuseIP/blacklist_plain_20250530",
        reverse_dns=True
    )

    launch_scan_task.delay(test_config.to_dict())
