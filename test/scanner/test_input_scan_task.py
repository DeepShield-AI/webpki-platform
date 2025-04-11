
import time
import pymysql
from celery.result import AsyncResult
from backend.config.config_loader import DB_CONFIG
from backend.config.scan_config import InputScanConfig, CTScanConfig
from backend.scanner.celery_scan_task import single_scan_task, launch_scan_task, process_target

test_config = InputScanConfig(
    "test_scan",
    proxy_host=None,
    proxy_port=None,
    input_list_file="./test/scanner/test_input_list.txt",
)

def test_launch_scan_task():

    result : AsyncResult = launch_scan_task.delay(test_config.to_dict())
    assert isinstance(result.get(timeout=50), bool)
    assert result.successful()

    time.sleep(15)
    conn = pymysql.connect(**DB_CONFIG)
    with conn.cursor() as cursor:
        cursor.execute("USE tls_handshake;")
        cursor.execute("SELECT * FROM tlshandshake WHERE destination_host=%s", ("www.example.com",))
        row = cursor.fetchone()
        assert row is not None


def test_process_target_task():

    result : AsyncResult = process_target.delay(
        "www.example.com",
        "23.32.239.58",
        test_config.to_dict(),
        "xxx",
        "xxx"
    )
    assert result.get(timeout=50) is None
    assert result.successful()

    time.sleep(10)
    conn = pymysql.connect(**DB_CONFIG)
    with conn.cursor() as cursor:
        cursor.execute("USE tls_handshake;")
        cursor.execute("SELECT * FROM tlshandshake WHERE destination_host=%s", ("www.example.com",))
        row = cursor.fetchone()
        assert row is not None


def test_single_scan_task():

    # result: bool= single_scan_task("www.example.com", test_config.to_dict())
    # assert isinstance(result, bool)
    # assert result == True

    result: AsyncResult = single_scan_task.delay("www.example.com", test_config.to_dict())
    assert isinstance(result.get(timeout=50), bool)
    assert result.successful()
