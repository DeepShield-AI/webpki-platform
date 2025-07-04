
'''
    统计 Top1M 网站中每个网站在 Nimbus 和 Sabre CT 日志中的 Associated Domain 数量
    分开统计，文章中的表格这样来写：
    CT 日志名称 | Top 1M 证书数量 | Associated Domain 数量 | TLS 扫描成功数量
    Nimbus  | 420021 + 12992 + 760038 + 2811 = 1,195,862        | 7314093 | ?? 
    Sabre   | 260013 + 17100 + 23817 + 360018 + 2865 = 663,813  | 1784209 | ?? 
'''

import sys
sys.path.append(r"D:\global_ca_monitor")

import os
import json, csv
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock, Thread
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.utils.json import custom_serializer, split_json_objects
from backend.utils.cert import get_sha256_hex_from_str
from backend.utils.domain_lookup import DomainLookup


# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]
print(len(list(rank_dict.keys())))


class RelatedDomains():

    def  __init__(
            self,
            log_name = "sabre",
            load_dir = r'D:/global_ca_monitor/data/group_top_domains_sabre',
            save_dir = r'./'
        ) -> None:

        self.log_name = log_name
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
        output_dict = {}
        # for rank in sorted(rank_dict.values()):
            # output_dict[rank] = set()

        while True:
            entry = self.queue.get()

            if entry is None:  # Poison pill to shut down the thread
                print("Poision detected")
                save_file = os.path.join(self.save_dir, f"1-related_domains_{self.log_name}.csv")
                with open(save_file, 'w', encoding='utf-8', newline='') as f:
                    print(f"Open {save_file}...")

                    writer = csv.writer(f)
                    writer.writerow(['related', 'target'])
                    for k, v in output_dict.items():
                        writer.writerow([k, list(v)])
                    break

            for related in entry["related"]:
                if related not in output_dict:
                    output_dict[related] = set()
                for target in entry["target"]:
                    rank = rank_dict[target]
                    output_dict[related].add(rank)

            self.queue.task_done()


    def scan_thread(self, file_path : str):

        if os.path.isfile(file_path):
            with open(file_path, "r", encoding='utf-8') as file:
                print(f'Reading {file_path}')
                data = file.read()

                for json_str in split_json_objects(data):
                    try:
                        entry = json.loads(json_str)
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

            with ThreadPoolExecutor(max_workers=2) as executor:

                for file_entry in os.scandir(self.load_dir):
                    # executor.submit(self.scan_thread, file_entry.path)
                    executor.submit(self.scan_thread, file_entry.path).result()

                executor.shutdown(wait=True)
                print("All threads finished.")

            self.queue.join()
            self.queue.put(None)
            self.saver_thread.join()


parser = RelatedDomains(
    log_name = "nimbus",
    load_dir = r'D:/global_ca_monitor/data/group_top_domains_nimbus',
    save_dir = r'./'
)
# parser = RelatedDomains()
parser.start()
