
from backend.config.scan_config import CTScanConfig
from backend.scanner.celery_scan_task import launch_scan_task

if __name__ == "__main__":
    test_config = CTScanConfig(
        scan_task_name="nimbus2025 1780M-1790M",
        output_file_dir=r"/home/tianyuz23/data/pki-internet-platform/data/ca_certs",
        proxy_host=None,
        proxy_port=None,
        scan_timeout=2,
        max_retry=10,
        ct_log_name="nimbus2025",
        ct_log_address="ct.cloudflare.com/logs/nimbus2025",
        entry_start= 1388888888,
        entry_end= 1390000000,
        window_size= 200
    )

    launch_scan_task(test_config.to_dict())

