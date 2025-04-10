
'''
    Update on 24/09/23
    Now domain scanner is integrated with Jarm
    The scanner can get Jarm TLS fingerprinting by adding scanning configuration
    Referenced with https://github.com/salesforce/jarm/blob/master/jarm.py
'''

import os
import csv
import json
import time
import hashlib
import threading
import subprocess

from datetime import datetime, timezone
from queue import PriorityQueue, Queue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.dialects.mysql import insert

from .jarm_fp_utils import *
from .scan_base import Scanner
from backend.config.config_loader import ZGRAB2_PATH, ZMAP_PATH
from backend.config.scan_config import InputScanConfig
from backend.config.config_loader import DEFAULT_IP_BLACKLIST
from backend.utils.cert import get_cert_sha256_hex_from_str
from backend.utils.type import ScanType, ScanStatusType
from backend.utils.json import custom_serializer
from backend.utils.network import resolve_host_dns
from backend.logger.logger import primary_logger

from backend.celery import celery_app
from celery import group
import redis
import time
import threading
import select
import socket
import socks
import codecs
import ipaddress
import http.client
import subprocess
import redis

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from dataclasses import dataclass
from celery.app.task import Task
from celery.result import AsyncResult

from backend.celery import celery_app
from backend.scanner.jarm_fp_utils import *
from backend.scanner.celery_monitor_task import monitor_scan_task
from backend.scanner.scan_manager import InputScanner
from backend.scanner.scan_by_ct import CTScanner
from backend.config.config_loader import ZGRAB2_PATH
from backend.config.scan_config import ScanConfig, InputScanConfig, CTScanConfig
from backend.utils.type import ScanType, ScanStatusType
from backend.utils.exception import RetriveError
from backend.logger.logger import primary_logger, get_logger

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
        self.scan_start_time = datetime.now(timezone.utc)

        # scan settings from scan config
        self.scan_name = scan_config.scan_process_name
        self.storage_dir = scan_config.output_file_dir
        self.max_threads_alloc = scan_config.max_tasks_parallel
        self.thread_workload = scan_config.single_task_workload

        self.proxy_host = scan_config.proxy_host
        self.proxy_port = scan_config.proxy_port
        self.scan_timeout = scan_config.scan_timeout
        self.max_retry = scan_config.max_retry

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()
        self.is_killed = False

        # logger
        self.logger = get_logger(f"scan-task-{self.scan_id}")

        # monitor task
        self.monitor_task_id = self._start_monitor_loop()

        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

    def _start_monitor_loop(self):
        def monitor_loop():
            while True:
                monitor_scan_task.delay(self.scan_id)
                time.sleep(30)

        self.monitor_thread = threading.Thread(
            target=monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()

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
    @abstractmethod
    def save_results(self):
        pass



class InputScanner(Scanner):

    def __init__(
            self,
            scan_config : InputScanConfig,
        ) -> None:

        super().__init__(scan_config)

        # scan settings from scan config
        self.input_file = scan_config.input_list_file
        self.enable_jarm = scan_config.enable_jarm
        self.scan_port = scan_config.scan_port



    def start(self, scan_config : InputScanConfig):
        """从文件中流式读取并提交任务，避免读入全部内存"""
        batch = []

        # read domain list from the input file
        self.current_index = self.begin_num
        with open(self.input_csv_file, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)

            for row in reader:
                if self.current_index > self.end_num:
                    break

                try:
                    rank, host = int(row[0]), row[1]
                except Exception:
                    rank = 0
                    host = row[0]

                self.task_queue.put((rank, host))
                self.current_index += 1

        with open(DOMAIN_FILE, 'r') as f:
            # 跳过前面的行
            for _ in range(start_line):
                f.readline()

            # 读取本批次
            for _ in range(BATCH_SIZE):
                line = f.readline()
                if not line:
                    break
                batch.append(line.strip())

        if not batch:
            print("[调度器] 已读完全部任务")
            return

        # 提交 Celery group 任务
        group(scan_domain_task.s(domain) for domain in batch)()
        print(f"[调度器] 提交了 {len(batch)} 个域名任务，起始行号: {start_line}")

        # 提交下一批任务
        stream_dispatch_task.delay(start_line + len(batch))


    def terminate(self):
        primary_logger.info("Terminating domain scan task...")
        self.crtl_c_event.set()  # 触发退出事件
        self.is_killed = True





@dataclass
class ScanStatusData():

    '''
        Scan Status Data contains all info for ScanStatus db model
        use this soly for updating ScanStatus model
    '''

    start_time : datetime = datetime.now(timezone.utc)
    end_time : datetime = None
    status : ScanStatusType = ScanStatusType.RUNNING

    scanned_domains : int = 0
    scanned_ips : int = 0
    scanned_entries : int = 0
    scanned_certs : int = 0

    success_count : int = 0
    error_count : int = 0


