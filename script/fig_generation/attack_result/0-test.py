
'''
    提取所有 Top 1M 的证书
    结果按照 a-z + _ 的形式存储到 27 个文件里
    仅存储：
    [
        {
            "target_domain" : xxx,
            "matched_certs" : [
                {
                    "sha256" : xxx,
                    "timestamp" : xxx,
                    "san" : xxx
                    "pub_key" : xxx
                },
                ...
            ]
        }
    ]
'''

import sys
sys.path.append(r"D:\global_ca_monitor")

import os
import json
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock, Thread
from backend.parser.pem_parser import ASN1Parser, PEMResult
from backend.utils.json import custom_serializer, split_json_objects
from backend.utils.cert import get_sha256_hex_from_str
from backend.utils.domain_lookup import DomainLookup

class ParseTopCerts():

    def  __init__(
            self,
            load_dir = r'H:/group_top_domains_nimbus',
            save_dir = r'D:/global_ca_monitor/data/cert_replica'
        ) -> None:

        self.load_dir = load_dir
        self.save_dir = save_dir
        self.look_up = DomainLookup()
        self.split_window = 100000
        self.queue = Queue()

        # @Debug only
        self.lock = Lock()
        self.count = 0
        self.total = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()


    def save_top_domain_certs(self):
        count = 0
        index = 0

        while True:
            save_file = os.path.join(self.save_dir, f"top_1m_{index * self.split_window}_{(index + 1) * self.split_window}")

            with open(save_file, 'w', encoding='utf-8') as f:
                print(f"Open {save_file}...")
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


    def scan_thread(self, file_path : str):

        if os.path.isfile(file_path):
            with open(file_path, "r") as file:
                data = file.read()

                for json_str in split_json_objects(data):
                    try:
                        entry = json.loads(json_str)
                        leaf_info = ASN1Parser.parse_pem_cert(entry["leaf"])

                        entry = {
                            "sha256" : get_sha256_hex_from_str(entry["leaf"]),
                            "timestamp" : entry["timestamp"],
                            "san" : list(set(leaf_info.subject_cn_list)),
                            "pub_key_alg" : leaf_info.pub_key_alg,
                            "pub_key" : leaf_info.spki
                        }
                        self.queue.put(entry)

                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")

        with self.lock:
            self.count += 1
        self.progress.update(self.progress_task, description=f"[green]Completed: {self.count}, [red]Total: {self.total}")
        self.progress.advance(self.progress_task)


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:

            # how many files here?
            self.total = sum(1 for file_entry in os.scandir(self.load_dir) if os.path.isfile(file_entry.path))
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

            self.saver_thread = Thread(target=self.save_top_domain_certs)
            self.saver_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.saver_thread.start()

            with ThreadPoolExecutor(max_workers=5) as executor:

                for file_entry in os.scandir(self.load_dir):
                    executor.submit(self.scan_thread, file_entry.path)
                    # executor.submit(self.scan_thread, file_entry.path).result()

                executor.shutdown(wait=True)
                print("All threads finished.")

            self.queue.join()
            self.queue.put(None)
            self.saver_thread.join()

parser = ParseTopCerts()
parser.start()
