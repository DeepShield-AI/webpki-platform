
# celery_app.py
from celery import Celery

# Redis 配置（默认本地 Redis）
BROKER_URL = 'redis://localhost:6379/0'
RESULT_BACKEND = 'redis://localhost:6379/1'

celery_app = Celery(
    'task_manager',
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=[
        'backend.scanner.celery_scan_task',
        'backend.scanner.celery_save_task',
        'backend.scanner.celery_monitor_task',
        'backend.analyzer.celery_save_task',
        'backend.analyzer.celery_cert_fp_task',
        'backend.analyzer.celery_cag_task',
        'backend.analyzer.celery_cert_parse_task',
        'backend.analyzer.celery_cert_security_task',
        'backend.analyzer.celery_web_security_task'
    ]
)

# 可选：加载配置文件
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Shanghai',
    enable_utc=True,
)
