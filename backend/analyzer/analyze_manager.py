
import time
import threading
from backend.logger.logger import primary_logger
from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.celery_save_task import batch_flush_results
from backend.analyzer.celery_cert_fp_task import build_all_from_table
from backend.analyzer.celery_cag_task import build_all

class AnalyzeManager():

    def __init__(
            self,
            analyze_config : AnalyzeConfig
        ) -> None:

        self.config = analyze_config

    def _start_batch_flush(self):
        def flush_loop():
            while True:
                batch_flush_results.delay()
                time.sleep(10)

        self.save_thread = threading.Thread(
            target=flush_loop,
            daemon=True
        )
        self.save_thread.start()
        primary_logger.info(f"Save thread started!")

    def start(self):
        # start save task
        self._start_batch_flush()

        # check flags
        if self.config.task_flag & AnalyzeConfig.TASK_CERT_FP:
            build_all_from_table.delay(self.config.cert_table)
        if self.config.task_flag & AnalyzeConfig.TASK_CAG:
            build_all.delay(self.config.out_dir)

        while True:
            pass
        