
import json
import pymysql
from backend.config.config_loader import DB_CONFIG
from backend.utils.cert import get_cert_sha256_hex_from_str
from backend.logger.logger import primary_logger
from backend.celery.celery_app import celery_app

'''
    result:
    input_scan_save_result.delay({
        "destination_host": destination,
        "destination_ip": destination_ip,
        "scan_time" : datetime.now(timezone.utc).isoformat(),
        "jarm": jarm,
        "jarm_hash": jarm_hash,
        "ssl_result": ssl_result
    })

    ssl_result:
        return {
            "tls_version" : tls_version,
            "tls_cipher" : tls_cipher,
            "peer_certs" : cert_pem,
            "error" : last_error
        }

    存储进两个数据库
    1. 将除了 cert_pem 之外的内容存进名为 tls_handshake db 的 tlshandshake table
    对于 cert_pem, get_cert_sha256_hex_from_str 计算 哈希值存入

    2. 将 cert_pem 存入 cert db 的 cert table
    使用 刚刚计算的 哈希作为 primary id

'''

@celery_app.task
def input_scan_save_result(result: dict):
    try:
        conn = pymysql.connect(**DB_CONFIG, database="tls_handshake")
        cert_conn = pymysql.connect(**DB_CONFIG, database="cert")

        destination_host = result.get("destination_host")
        destination_ip = result.get("destination_ip")
        scan_time = result.get("scan_time")
        jarm = result.get("jarm")
        jarm_hash = result.get("jarm_hash")
        ssl_result = result.get("ssl_result", {})

        tls_version = ssl_result.get("tls_version")
        tls_cipher = ssl_result.get("tls_cipher")
        peer_certs = ssl_result.get("peer_certs")
        error = ssl_result.get("error")

        # 计算证书哈希值
        cert_hashes = [
            get_cert_sha256_hex_from_str(cert_pem)
            for cert_pem in peer_certs
        ]

        # === Step 1: 存入 cert 数据库 cert 表 ===
        for cert_hash, cert_pem in zip(cert_hashes, peer_certs):
            with cert_conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT IGNORE INTO cert (cert_hash, cert_pem)
                    VALUES (%s, %s)
                    """,
                    (cert_hash, cert_pem)
                )
            cert_conn.commit()

        # === Step 2: 存入 tls_handshake 表，存所有 cert_hash ===
        cert_hash_list_json = json.dumps(cert_hashes)  # list -> string for DB

        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO tlshandshake (
                    destination_host, destination_ip, scan_time, jarm, jarm_hash,
                    tls_version, tls_cipher, cert_hash_list, error
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    destination_host,
                    destination_ip,
                    scan_time,
                    jarm,
                    jarm_hash,
                    tls_version,
                    tls_cipher,
                    cert_hash_list_json,
                    error
                )
            )
        conn.commit()

    except Exception as e:
        primary_logger.error(f"[input_scan_save_result] Error saving result: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        try:
            cert_conn.close()
        except:
            pass
