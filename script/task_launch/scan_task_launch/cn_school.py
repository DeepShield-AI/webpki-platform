
from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = InputScanConfig(
        "CN_EDU_20250630",
        proxy_host=None,
        proxy_port=None,
        input_list_file=r"/home/tianyuz23/data/pki-internet-platform/data/school_domains/cn/domains.txt",
        output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/school_domains/cn/",
    )

    launch_scan_task(test_config.to_dict())
