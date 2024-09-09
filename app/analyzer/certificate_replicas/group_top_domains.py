
'''
    First step after ct data collection:
    Find all certs for Top-1M domains, and store them into separate files
'''

import threading
import asyncio
import aiofiles
import hashlib
import json
import os

from queue import Queue
from threading import Lock
from aiofiles.os import listdir
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID

from ...parser.pem_parser import PEMParser
from ...utils.domain_lookup import DomainLookup
from ...utils.json import custom_serializer
from ...logger.logger import my_logger


class DataParser():

    def  __init__(
            self,
            log_name = "sabre2024h1",
            load_dir = r'H:/sabre2024h1',
            save_dir = r'D:/data/group_top_domains_sabre'
        ) -> None:

        self.log_name = log_name
        self.load_dir = load_dir
        self.save_dir = save_dir

        self.look_up = DomainLookup()
        self.split_window = 100000
        self.queue = Queue()

        # @Debug only
        self.count = 0
        self.total = 0
        self.lock = Lock()
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()

        self.saver_thread = threading.Thread(target=self.save_top_domain_certs)
        # saver_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
        self.saver_thread.start()


    def fetch_san_from_raw(self, cert : str):
        pem_result = PEMParser.parse_pem_cert(cert)
        return set(pem_result.subject)


    def scan_file(self, data: str):
        for entry in data.values():
            if entry['leaf'] is not None:
                san_list = self.fetch_san_from_raw(entry['leaf'])

                for subject in san_list:
                    target_domain_list = self.look_up.lookup(subject)
                    if len(target_domain_list) > 0:
                        self.queue.put(entry)
                        break

        with self.lock:
            self.count += 1
        self.progress.update(self.progress_task, description=f"[green]Completed: {self.count}, [red]Total: {self.total}")
        self.progress.advance(self.progress_task)


    def save_top_domain_certs(self):
        count = 0
        index = 0

        while True:
            save_file = os.path.join(self.save_dir, f"top_1m_{self.log_name}_{index * self.split_window}_{(index + 1) * self.split_window}")
            my_logger.info(f"Opening {save_file}...")

            with open(save_file, 'w') as f:
                while count <= self.split_window:
                    top_cert_entry = self.queue.get()

                    if top_cert_entry is None:  # Poison pill to shut down the thread
                        print("Poision detected")
                        return

                    json_str = json.dumps(top_cert_entry, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                    f.write(json_str + '\n')
                    self.queue.task_done()
                    count += 1

                count = 0
                index += 1


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:

            self.total = sum(1 for file_entry in os.scandir(self.load_dir) if os.path.isfile(file_entry.path))
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

            with ThreadPoolExecutor(max_workers=40) as executor:

                for file_entry in os.scandir(self.load_dir):
                    file_path = file_entry.path

                    if os.path.isfile(file_path):
                        with open(file_path, "r") as file:
                            data = json.load(file)
                            executor.submit(self.scan_file, data)
    
                executor.shutdown(wait=True)
                my_logger.info("All threads finished.")

            # Wait for all elements in queue to be handled
            self.queue.join()

            # Send the poison pill to stop the saver thread
            self.queue.put(None)
            self.saver_thread.join()

