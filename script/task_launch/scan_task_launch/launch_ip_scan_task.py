
from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = InputScanConfig(
        "IPv4 20250628",
        proxy_host=None,
        proxy_port=None,
        input_list_file=r"/root/open443.txt",
        skip_first=3630000
    )

    launch_scan_task(test_config.to_dict())
