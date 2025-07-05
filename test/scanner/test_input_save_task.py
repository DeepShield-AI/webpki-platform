
# test_input_save_task.py

import pymysql
import json
from datetime import datetime
from celery.result import AsyncResult
from backend.scanner.celery_save_task import input_scan_save_result
from backend.config.config_loader import DB_CONFIG
from backend.utils.cert import get_sha256_hex_from_str


def test_input_scan_save_result():
    # 构造假 cert PEM 列表
    fake_certs = [
        "-----BEGIN CERTIFICATE-----\nMIIBFAFAKECERTDATA1==\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\nMIIBFAFAKECERTDATA2==\n-----END CERTIFICATE-----"
    ]

    test_ssl_result = {
        "tls_version": "TLS 1.2",
        "tls_cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "peer_certs": fake_certs,
        "error": "test error"
    }

    test_result = {
        "destination_host": "example.com",
        "destination_ip": "114.11.411.41",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "jarm": "some-jarm",
        "jarm_hash": "jarm-hash-value",
        "ssl_result": test_ssl_result
    }

    # 执行保存任务
    result : AsyncResult = input_scan_save_result.delay(test_result)
    assert result.get(timeout=50) is None
    assert result.successful()

    # 计算 hash
    cert_hashes = [get_sha256_hex_from_str(pem) for pem in fake_certs]

    # this is test, so we use single conn here
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cursor:
            # 验证 cert 表中包含 hash
            cursor.execute("USE cert;")
            for cert_hash in cert_hashes:
                cursor.execute("SELECT cert_hash FROM cert WHERE cert_hash = %s", (cert_hash,))
                result = cursor.fetchone()
                assert result is not None, f"cert_hash {cert_hash} not inserted"
                assert result[0] == cert_hash, f"cert_hash mismatch: expected {cert_hash}, got {result[0]}"

            # 验证 tlshandshake 表中包含 cert_hash_list
            cursor.execute("USE tls_handshake;")
            cursor.execute("""
                SELECT destination_host, destination_ip, cert_hash_list
                FROM tlshandshake
                WHERE destination_host = %s
                ORDER BY scan_time DESC
                LIMIT 1
            """, (test_result["destination_host"],))
            row = cursor.fetchone()
            assert row is not None, "tlshandshake row not inserted"
            dest, ip, cert_hash_list_str = row
            assert dest == test_result["destination_host"], f"destination_host mismatch: {dest}"
            assert ip == test_result["destination_ip"], f"destination_ip mismatch: {ip}"
            hash_list = json.loads(cert_hash_list_str)
            assert set(hash_list) == set(cert_hashes), f"cert_hash_list mismatch: expected {cert_hashes}, got {hash_list}"

    finally:
        conn.close()
