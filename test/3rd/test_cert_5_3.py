
from backend.config.scan_config import CTScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = CTScanConfig(
        scan_task_name="yeti2025 1760M-1770M",
        output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/ca_certs",
        proxy_host=None,
        proxy_port=None,
        scan_timeout=2,
        max_retry=10,
        ct_log_name="yeti2025",
        ct_log_address="yeti2025.ct.digicert.com/log",
        entry_start= 1760000000,
        entry_end= 1770000000,
        window_size= 200
    )

    launch_scan_task.delay(test_config.to_dict())

