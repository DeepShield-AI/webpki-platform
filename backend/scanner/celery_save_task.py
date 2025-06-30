
import os
import json
import redis
import pymysql
from backend.config.config_loader import DB_CONFIG
from backend.utils.cert import get_cert_sha256_hex_from_str
from backend.logger.logger import primary_logger
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_tls

r = redis.Redis()

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
    primary_logger.debug("enter")
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

        primary_logger.debug(f"Saving data for {destination_host} : {destination_ip}")
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


@celery_app.task
def batch_flush_results(min_batch_size=2000):

    queue_len = r.llen('scan_results_queue')
    primary_logger.info(f"Current LLEN: {queue_len}")

    if queue_len > 2 * min_batch_size:
        batch_size = int(queue_len / 2)
    else:
        batch_size = min_batch_size

    results = []
    primary_logger.info(f"Batch Size: {batch_size}")
    for _ in range(batch_size):
        raw = r.lpop("scan_results_queue")
        if raw:
            results.append(json.loads(raw))

    primary_logger.debug(f"Insert batch with len {len(results)}")
    if not results:
        return

    cert_conn = engine_cert.raw_connection()
    tls_conn = engine_tls.raw_connection()

    try:
        # --- Step 1: 批量写入 cert 表 ---
        cert_data = []
        for result in results:

            ct_cert = result.get("cert_pem", None)
            if ct_cert is None:
                # this is TLS scan result
                peer_certs = result.get("ssl_result", {}).get("peer_certs", [])
                for cert_pem in peer_certs:
                    cert_hash = get_cert_sha256_hex_from_str(cert_pem)
                    cert_data.append((cert_hash, cert_pem))
            else:
                # this is CT scan result
                cert_hash = get_cert_sha256_hex_from_str(ct_cert)
                cert_data.append((cert_hash, ct_cert))

                if result.get("is_ca_cert", False):
                    out_dir = result.get("out_dir", None)
                    if out_dir is not None:
                        with open(os.path.join(out_dir, "unique_ca_certs"), "a") as f:
                            f.write(ct_cert)

        if cert_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT IGNORE INTO cert (cert_hash, cert_pem) VALUES (%s, %s)",
                    cert_data
                )
            cert_conn.commit()

        # --- Step 2: 批量写入 tlshandshake 表 ---
        tls_data = []
        for result in results:

            ct_cert = result.get("cert_pem", None)
            if ct_cert is not None: continue

            ssl_result = result.get("ssl_result", {})
            peer_certs = ssl_result.get("peer_certs", [])
            cert_hashes = [
                get_cert_sha256_hex_from_str(cert_pem)
                for cert_pem in peer_certs
            ]
            tls_data.append((
                result.get("destination_host"),
                result.get("destination_ip"),
                result.get("scan_time"),
                result.get("jarm"),
                result.get("jarm_hash"),
                ssl_result.get("tls_version"),
                ssl_result.get("tls_cipher"),
                json.dumps(cert_hashes),
                ssl_result.get("error")
            ))

            # check for file output
            out_file = result.get("out_file", None)
            if out_file:
                with open(out_file, "a") as out:
                    out.write(json.dumps(result))
                    out.write("\n")

        if tls_data:
            with tls_conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO tlshandshake (
                        destination_host, destination_ip, scan_time, jarm, jarm_hash,
                        tls_version, tls_cipher, cert_hash_list, error
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    tls_data
                )
            tls_conn.commit()

    except Exception as e:
        primary_logger.error(f"[batch_flush_results] Error: {e}")
    finally:
        cert_conn.close()
        tls_conn.close()
