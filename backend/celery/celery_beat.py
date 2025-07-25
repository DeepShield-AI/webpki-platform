
# celery_beat.py
# here lays the global celery tasks

from celery.schedules import crontab

beat_schedule = {
    'scanner_flush_results': {
        'task': 'backend.scanner.celery_save_task.batch_flush_results',
        'schedule': 10.0,
        'options': {'queue': 'save_queue'},
    },
    'analyzer_flush_results': {
        'task': 'backend.analyzer.celery_save_task.batch_flush_results',
        'schedule': 10.0,
        'options': {'queue': 'save_queue'},
    },
    'flush_redis_queue_daily': {
        'task': 'backend.celery.celery_redis.flush_redis_queue',
        'schedule': 6 * 3600,  # 每 6 小时执行一次
        'options': {'queue': 'save_queue'},
    },
    'flush_crl_cache': {
        'task': 'backend.analyzer.celery_cert_revocation_task.cleanup_crl_cache',
        'schedule': 1 * 3600,
        'options': {'queue': 'save_queue'},
    },
}
