
'''
    Update on 24/09/23
    Now domain scanner is integrated with Jarm
    The scanner can get Jarm TLS fingerprinting by adding scanning configuration
    Referenced with https://github.com/salesforce/jarm/blob/master/jarm.py
'''

# === 标准库 ===
import os
import csv
import json
import math
import time
import base64
import redis
import threading
from queue import Queue
from threading import Lock
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

# === 第三方库 ===
import requests
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import Encoding
from celery import group

# === 项目内部 ===
from backend.config.scan_config import ScanConfig, InputScanConfig, CTScanConfig
from backend.logger.logger import primary_logger, get_logger
from backend.utils.type import ScanType, ScanStatusType
from backend.utils.cert import get_cert_sha256_hex_from_str
from backend.utils.json import custom_serializer
from backend.scanner.jarm_fp_utils import *
from backend.scanner.celery_monitor_task import monitor_scan_task
from backend.scanner.celery_save_task import batch_flush_results
from backend.parser.ct_parser import *

r = redis.Redis()

# This class is the one that performs big scanning,
# has two modes: scan by input list and scan CT log
# constructed when there is an scan task generated
class Scanner(ABC):

    def __init__(
            self,
            task_id : str,
            scan_config : ScanConfig,
        ) -> None:

        self.scan_id = task_id
        self.scan_config = scan_config
        self.scan_start_time = datetime.now(timezone.utc)

        # ouptput path
        if not os.path.exists(self.scan_config.output_file_dir):
            os.makedirs(self.scan_config.output_file_dir)

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()
        self.is_killed = False

        # logger
        self.logger = get_logger(f"scan-task-{self.scan_id}")

        # monitor task
        # self.monitor_task_id = self._start_monitor_loop()


    def _start_monitor_loop(self):
        def monitor_loop():
            while True:
                monitor_scan_task.delay(self.scan_id, self.scan_config.scan_task_name)
                time.sleep(30)

        self.monitor_thread = threading.Thread(
            target=monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        primary_logger.info(f"Monitor to {self.scan_id} started!")

    '''
        @Methods for all types of scans
        @Use abstract methods here
    '''
    # here we init a new monitor task for this scan
    @abstractmethod
    def start(self):
        pass
    @abstractmethod
    def terminate(self):
        pass
    @abstractmethod
    def pause(self):
        pass
    @abstractmethod
    def resume(self):
        pass


class InputScanner(Scanner):

    def __init__(
            self,
            task_id : str,
            scan_config : InputScanConfig,
        ) -> None:
        super().__init__(task_id, scan_config)

        # scan settings from scan config
        self.input_file = scan_config.input_list_file
        self.skip_first = scan_config.skip_first
        self.recursive_depth = scan_config.recursive_depth

    def _start_recursive_handler(self):
        def flush_loop():
            while True:
                batch_flush_results.delay()
                time.sleep(2)

        self.recursive_thread = threading.Thread(
            target=flush_loop,
            daemon=True
        )
        self.recursive_thread.start()
        primary_logger.info(f"Recursive thread started!")


    def _start_batch_flush(self):
        def flush_loop():
            while True:
                batch_flush_results.delay()
                time.sleep(10)

        self.monitor_thread = threading.Thread(
            target=flush_loop,
            daemon=True
        )
        self.monitor_thread.start()
        primary_logger.info(f"Save thread started!")

    def start(self):
        # start save task
        # self._start_batch_flush()

        # start related domain save task
        # 暂时先不存储相关联域名
        # self._start_recursive_handler()

        # avoid loop import
        from backend.scanner.celery_scan_task import single_scan_task
        with open(self.input_file, 'r', encoding='utf-8') as input_file:
            for i, row in enumerate(input_file):
                if i < self.skip_first: continue
                row : str
                single_scan_task.delay(row.strip(), self.scan_config.to_dict(), self.recursive_depth)

                while True:
                    if r.llen('celery') <= 1000: break
                    time.sleep(1)

    def terminate(self):
        primary_logger.info("Terminating domain scan task...")
        self.crtl_c_event.set()  # 触发退出事件
        self.is_killed = True

    def pause(self):
        pass

    def resume(self):
        pass


class CTScanner(Scanner):

    def __init__(
            self,
            task_id : str,
            scan_config : CTScanConfig
        ) -> None:

        super().__init__(task_id, scan_config)

        # scan settings from scan config
        self.ct_log_name = scan_config.ct_log_name
        self.ct_log_address = scan_config.ct_log_address
        self.entry_start = scan_config.entry_start
        self.entry_end = scan_config.entry_end
        self.window_size = scan_config.window_size
        self.out_dir = scan_config.output_file_dir

    def start(self):

        # read old unique_ca_certs file and compute all the existing sha256
        self.unique_ca_certs_file = os.path.join(self.out_dir, "unique_ca_certs")
        try:
            with open(self.unique_ca_certs_file, 'r') as f:
                cert_data = f.read()

            certificates = cert_data.split("-----END CERTIFICATE-----\n")
            for cert in certificates:
                if "-----BEGIN CERTIFICATE-----" in cert:
                    cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                    cert_sha256 = get_cert_sha256_hex_from_str(cert)
                    self.ca_sha_256_set.add(cert_sha256)

            primary_logger.info(f"Load {len(certificates)} old CA certs")
        except FileNotFoundError:
            pass

        # avoid loop import
        from backend.scanner.celery_scan_task import single_ct_scan_task
        start = self.entry_start
        while start < self.entry_end:
            end = start + self.window_size
            if end < self.entry_end:
                end = self.entry_end
            single_ct_scan_task.delay(start, end, self.scan_config.to_dict())
            start = end
            # This is necessary for hosts that on low memory
            time.sleep(0.5)

    def terminate(self):
        primary_logger.info("Terminating CT scan task...")
        self.crtl_c_event.set()  # 触发退出事件
        self.is_killed = True

    def pause(self):
        pass
    def resume(self):
        pass
