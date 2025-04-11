
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

    cert_conn = engine_cert.raw_connection()

    try:
        cert_data = []
        for result in results:
            if result.get("flag", "") == AnalyzeConfig.TASK_CERT_FP:
                cert_hash = result.get("cert_hash", "")
                cert_fp = result.get("cert_fp", "")
                cert_data.append((cert_hash, cert_fp))

        if cert_data:
            with cert_conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT IGNORE INTO cert_fp (cert_hash, cert_fp) VALUES (%s, %s)",
                    cert_data
                )
            cert_conn.commit()

    except Exception as e:
        primary_logger.error(f"[batch_flush_results] Error: {e}")
    finally:
        cert_conn.close()
