from celery_app import celery_app
from logger.logger import primary_logger

@celery_app.task(bind=True)
def start_task_async(self, task_id: int):
    from task_manager import g_manager  # 延迟导入避免循环

    task = g_manager.submitted_task.get(task_id)
    if not task:
        primary_logger.warning(f"[Celery] Task {task_id} not found.")
        return

    primary_logger.info(f"[Celery] Starting task {task_id}...")

    try:
        g_manager.running_task[task_id] = task
        g_manager.submitted_task.pop(task_id)

        g_manager.manager_map[task.task_type].start_task(task_id)
    except Exception as e:
        primary_logger.error(f"[Celery] Task {task_id} failed: {e}")
    finally:
        g_manager.running_task.pop(task_id, None)
