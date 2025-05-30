
import os, csv
import json
import redis
from backend.config.analyze_config import AnalyzeConfig
from backend.logger.logger import primary_logger
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert

r = redis.Redis()


# TODO: problem: inserted 2580, only got 2290 lines, need to know why?
@celery_app.task
def batch_flush_results(max_batch_size=2000):
    results = []
    for _ in range(max_batch_size):
        raw = r.lpop("analyze_results_queue")
        if raw:
            results.append(json.loads(raw))

    primary_logger.debug(f"Insert batch with len {len(results)}")
    if not results:
        return

    # cert asn1 fp
    cert_fp_data = []
    cert_conn = engine_cert.raw_connection()

    # cag node and edge
    cag_node_file = None
    cag_node_file_writer = None
    cag_edge_file = None
    cag_edge_file_writer = None

    for result in results:
        try:
            if result.get("flag", "") == AnalyzeConfig.TASK_CERT_FP:
                cert_hash = result.get("cert_hash", "")
                cert_fp = result.get("cert_fp", "")
                cert_fp_data.append((cert_hash, cert_fp))

            if result.get("flag", "") == AnalyzeConfig.TASK_CAG:

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

        except Exception as e:
            primary_logger.error(f"[batch_flush_results] Error: {e}")

    try:
        if cert_fp_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT IGNORE INTO cert_fp (cert_hash, cert_fp) VALUES (%s, %s)",
                    cert_fp_data
                )
            cert_conn.commit()

    except Exception as e:
        primary_logger.error(f"[batch_flush_results] Error: {e}")

    cert_conn.close()
    cag_node_file.close()
    cag_edge_file.close()
