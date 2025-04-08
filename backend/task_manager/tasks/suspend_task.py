
from celery_app import celery_app
from logger.logger import primary_logger

@celery_app.task(bind=True)
def suspend_task_async(self, task_id: int):
    from task_manager import g_manager

    task = g_manager.running_task.get(task_id)
    if not task:
        primary_logger.warning(f"[Celery] Task {task_id} not running.")
        return

    try:
        primary_logger.info(f"[Celery] Suspending task {task_id}...")
        g_manager.manager_map[task.task_type].suspend_task(task_id)
    except Exception as e:
        primary_logger.error(f"[Celery] Failed to suspend task {task_id}: {e}")
