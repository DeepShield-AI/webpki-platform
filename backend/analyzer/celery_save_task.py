
import os, csv
import json
import redis
import base64
from backend.config.analyze_config import AnalyzeConfig
from backend.logger.logger import primary_logger
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_ca

r = redis.Redis()


# TODO: problem: inserted 2580, only got 2290 lines, need to know why?
@celery_app.task
def batch_flush_results(min_batch_size=3000):

    queue_len = r.llen('analyze_results_queue')
    primary_logger.info(f"Current LLEN: {queue_len}")

    if queue_len > 2 * min_batch_size:
        batch_size = int(queue_len / 2)
    else:
        batch_size = min_batch_size

    results = []
    for _ in range(batch_size):
        raw = r.lpop("analyze_results_queue")
        if raw:
            results.append(json.loads(raw))

    primary_logger.debug(f"Insert batch with len {len(results)}")
    if not results:
        return

    # cert parse data
    cert_parse_data = []

    # cert asn1 fp
    cert_fp_data = []
    cert_conn = engine_cert.raw_connection()

    # cag node and edge
    cag_node_file = None
    cag_node_file_writer = None
    cag_edge_file = None
    cag_edge_file_writer = None

    # cert_security
    cert_security_file = None

    # web-security
    web_security_file = None

    # ca info
    ca_data = []
    ca_conn = engine_ca.raw_connection()

    # cert revoke
    cert_revoke_data = []

    for result in results:
        try:
            if result.get("flag", "") == AnalyzeConfig.TASK_CERT_FP:
                cert_fp_data.append((
                    result.get("id", ""),
                    json.dumps(result.get("fp", ""))
                ))

            elif result.get("flag", "") == AnalyzeConfig.TASK_CERT_PARSE:

                cert_parse_data.append((
                    result.get("id", ""),
                    result.get("sha256", ""),
                    result.get("serial", ""),
                    json.dumps(result.get("subject_cn_list", "")),  # make sure this is str type
                    json.dumps(result.get("subject", "")),
                    json.dumps(result.get("issuer", "")),
                    result.get("spkisha256", ""),
                    result.get("ski", ""),
                    result.get("not_valid_before", ""),
                    result.get("not_valid_after", ""),
                    result.get("type", "")
                ))

            elif result.get("flag", "") == AnalyzeConfig.TASK_CERT_REVOKE:

                primary_logger.info(result)

                revoke_result = result.get("result", {})
                cert_revoke_data.append((
                    result.get("id", ""),
                    result.get("type", ""),
                    revoke_result.get("dist_point", ""),
                    revoke_result.get("request_time", ""),
                    revoke_result.get("status", ""),
                    revoke_result.get("revoke_time", ""),
                    revoke_result.get("reason_flag", "")
                ))

            elif result.get("flag", "") == AnalyzeConfig.TASK_CAG:

                out_dir = result.get("out_dir", "/data/default_out")
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)

                if not cag_node_file:
                    cag_node_file = open(os.path.join(out_dir, "cag_node.csv"), "a", encoding='utf-8', newline='')
                    cag_node_file_writer = csv.writer(cag_node_file)

                if not cag_edge_file:
                    cag_edge_file = open(os.path.join(out_dir, "cag_edge.csv"), "a", encoding='utf-8', newline='')
                    cag_edge_file_writer = csv.writer(cag_edge_file)

                if result.get("cag_type", "") == "node":
                    id = result.get("id", "")
                    name = result.get("name", "")
                    _type = result.get("type", "")
                    cag_node_file_writer.writerow([id, name, _type])

                if result.get("cag_type", "") == "edge":
                    relation = result.get("relation", "")
                    source = result.get("source", "")
                    target = result.get("target", "")
                    cag_edge_file_writer.writerow([relation, source, target])

            elif result.get("flag", "") == AnalyzeConfig.TASK_CERT_SECURITY:

                out_dir = result.get("out_dir", "/data/default_out")
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)

                if not cert_security_file:
                    cert_security_file = open(os.path.join(out_dir, "cert_security.json"), "a", encoding='utf-8', newline='')

                json_result = json.dumps({
                    "sha256" : result.get("sha256", ""),
                    "error_code" : result.get("error_code", ""),
                    "error_info" : result.get("error_info", "")
                })
                cert_security_file.write(json_result + '\n')

            elif result.get("flag", "") == AnalyzeConfig.TASK_WEB_SECURITY:

                out_dir = result.get("out_dir", "/data/default_out")
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)

                if not web_security_file:
                    web_security_file = open(os.path.join(out_dir, "web_security.json"), "a", encoding='utf-8', newline='')

                json_result = json.dumps({
                    "domain" : result.get("domain", ""),
                    "ip" : result.get("ip", ""),
                    "tls_version" : result.get("tls_version", ""),
                    "tls_cipher" : result.get("tls_cipher", ""),
                    "cert_hash_list" : result.get("cert_hash_list", ""),
                    "error_code" : result.get("error_code", "")
                })
                web_security_file.write(json_result + '\n')

            elif result.get("flag", "") == AnalyzeConfig.TASK_CA_PROFILE:
                primary_logger.debug(json.dumps(result.get("spki", "")))

                ca_data.append((
                    result.get("ca_sha256", ""),
                    json.dumps(result.get("subject", "")),
                    base64.b64decode(result.get("spki", "")),
                    result.get("ski", ""),
                    result.get("cert_id", ""),
                ))

        except Exception as e:
            primary_logger.error(f"[batch_flush_results] Error: {e}")

    try:
        if cert_parse_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT IGNORE INTO cert_search
                    (id, sha256, serial, subject_cn_list, subject, issuer,
                    spkisha256, ski, not_valid_before, not_valid_after, type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    cert_parse_data
                )
            cert_conn.commit()

        if cert_revoke_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO cert_revocation
                    (cert_id, type, dist_point, request_time, status, revoke_time, reason_flag)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    cert_revoke_data
                )
            cert_conn.commit()

        if cert_fp_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT IGNORE INTO cert_fp (id, cert_fp) VALUES (%s, %s)",
                    cert_fp_data
                )
            cert_conn.commit()

        if ca_data:
            with ca_conn.cursor() as cursor:
                # 1. 更新已有记录：追加 sha256 到 certs（如果还没有）
                ca_data_update = [
                    (cert_id, ca_sha256, str(cert_id))
                    for ca_sha256, subject_json, spki, ski, cert_id in ca_data
                ]
                cursor.executemany("""
                    UPDATE ca
                    SET certs = JSON_ARRAY_APPEND(certs, '$', %s)
                    WHERE sha256 = %s
                    AND JSON_CONTAINS(certs, JSON_QUOTE(%s)) = 0
                """, ca_data_update)

                # 2. 插入新记录（如果不存在）
                cursor.executemany("""
                    INSERT IGNORE INTO ca (sha256, subject, spki, ski, certs)
                    VALUES (%s, %s, %s, %s, JSON_ARRAY(%s))
                """, ca_data)

            ca_conn.commit()

    except Exception as e:
        primary_logger.error(f"[batch_flush_results] Error: {e}")

    cert_conn.close()
    ca_conn.close()

    if cag_node_file: cag_node_file.close()
    if cag_edge_file: cag_edge_file.close()
    if cert_security_file: cert_security_file.close()
    if web_security_file: web_security_file.close()
