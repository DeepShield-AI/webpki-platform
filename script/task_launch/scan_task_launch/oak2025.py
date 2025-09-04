
from backend.config.scan_config import CTScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = CTScanConfig(
        scan_task_name="oak2025h2 1780M-1790M",
        output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/ca_certs",
        proxy_host=None,
        proxy_port=None,
        scan_timeout=2,
        max_retry=10,
        ct_log_name="oak2025h2",
        ct_log_address="oak.ct.letsencrypt.org/2025h2",
        entry_start= 1311111111,
        entry_end= 1320000000,
        window_size= 200
    )

    launch_scan_task(test_config.to_dict())

