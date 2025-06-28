
import redis
from backend.celery.celery_app import celery_app

@celery_app.task
def flush_redis_queue():
    r = redis.Redis()
    # 6h过期
    r.expire("crawled_domains", 1 * 6 * 3600)
    r.expire("scan_results_queue", 1 * 6 * 3600)
    r.expire("analyze_results_queue", 1 * 6 * 3600)
