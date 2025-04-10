
import redis
import pymysql
from celery import shared_task
from celery.result import AsyncResult
from datetime import datetime, timezone
from backend.config.config_loader import DB_CONFIG
from backend.celery.celery_app import celery_app

r = redis.Redis()

@shared_task
def monitor_scan_task(scan_task_id : str, scan_task_name : str):
    result = AsyncResult(scan_task_id)
    status = result.status.lower()
    progress = r.get(f"task:{scan_task_id}:progress")
    start_time_raw = r.get(f"task:{scan_task_id}:start_time")

    if start_time_raw:
        start_time = datetime.fromisoformat(start_time_raw.decode())
        run_time = (datetime.now(timezone.utc) - start_time).total_seconds()
    else:
        # TODO:
        # means the monitoring task is finished?
        run_time = None

    progress_str = progress.decode() if progress else "N/A"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = pymysql.connect(**DB_CONFIG, database="scan_status")
        cursor = conn.cursor()

        # 尝试更新，找不到就插入
        update_sql = """
            UPDATE scan_status
            SET status=%s, progress=%s, run_time=%s, last_update=%s
            WHERE task_id=%s
        """
        rows = cursor.execute(update_sql, (status, progress_str, run_time, now, scan_task_id))

        if rows == 0:
            insert_sql = """
                INSERT INTO scan_status (task_id, task_name, status, progress, run_time, start_time, last_update)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_sql, (scan_task_id, scan_task_name, status, progress_str, run_time, now, now))

        conn.commit()
        error_msg = None
    except Exception as e:
        error_msg = (f"[ERROR] MySQL error: {e}")
    finally:
        cursor.close()
        conn.close()
        return error_msg


# TODO: add exiting logic
# such as when the scan status is complete
