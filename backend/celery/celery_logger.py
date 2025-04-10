
import logging

celery_logger = logging.getLogger("TaskManager")
celery_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
celery_logger.addHandler(ch)
