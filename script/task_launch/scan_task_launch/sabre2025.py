
from backend.config.scan_config import CTScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = CTScanConfig(
        scan_task_name="sabre2025h2 1780M-1790M",
        output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/ca_certs",
        proxy_host=None,
        proxy_port=None,
        scan_timeout=2,
        max_retry=10,
        ct_log_name="sabre2025h2",
        ct_log_address="sabre2025h2.ct.sectigo.com",
        entry_start= 620000000,
        entry_end= 621000000,
        window_size= 20
    )

    launch_scan_task(test_config.to_dict())

