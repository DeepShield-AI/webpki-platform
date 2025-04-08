
from celery_app import celery_app
from logger.logger import primary_logger

@celery_app.task(bind=True)
def resume_task_async(self, task_id: int):
    from task_manager import g_manager

    task = g_manager.task_dict.get(task_id)
    if not task:
        primary_logger.warning(f"[Celery] Task {task_id} not found.")
        return

    try:
        primary_logger.info(f"[Celery] Resuming task {task_id}...")
        g_manager.manager_map[task.task_type].resume_task(task_id)
    except Exception as e:
        primary_logger.error(f"[Celery] Failed to resume task {task_id}: {e}")
