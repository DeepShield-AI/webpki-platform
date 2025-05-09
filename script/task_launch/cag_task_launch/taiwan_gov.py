
# scan for taiwan_gov with the seed

from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = InputScanConfig(
        "Taiwan_Gov 20250509",
        proxy_host=None,
        proxy_port=None,
        input_list_file=r"seed",
        recursive_depth=3
    )

    launch_scan_task.delay(test_config.to_dict())
