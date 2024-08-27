
import os
import json
from ...parser.pem_parser import PEMParser, PEMResult
from ...utils.domain_lookup import DomainLookup
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock


class DataParser():

    def  __init__(
            self,
            load_dir = r'H:/sabre2024h1',
            save_dir = r'H:/top_1m_collected'
        ) -> None:

        self.load_dir = load_dir
        self.save_dir = save_dir
        self.look_up = DomainLookup()

        # 锁表，用于每个文件的锁
        self.file_dict_lock = Lock()  # 用于保护 file_locks 的锁
        self.file_locks = {}

        # @Debug only
        self.lock = Lock()
        self.count = 0
        self.total = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()


    def scan_thread(self, file_path : str):
        with open(file_path, "r") as file:
            data = json.load(file)

            for entry in data.values():
                if entry['leaf'] != None:
                    san_list = self.fetch_san_from_raw(entry['leaf'])

                    # Compare san_list to top-1m
                    matched_domains = set()
                    for subject in san_list:
                        target_domain_list = self.look_up.lookup(subject)
                        for target_domain in target_domain_list:
                            matched_domains.add(target_domain)

                    self.save(entry, matched_domains)

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
            self.total = sum(1 for filename in os.listdir(self.load_dir) if os.path.isfile(os.path.join(self.load_dir, filename)))
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

            with ThreadPoolExecutor(max_workers=100) as executor:

                for filename in os.listdir(self.load_dir):
                    file_path = os.path.join(self.load_dir, filename)

                    if os.path.isfile(file_path):
                        executor.submit(self.scan_thread, file_path)
 
                executor.shutdown(wait=True)
                print("All threads finished.")
        

    def fetch_san_from_raw(self, cert : str):
        pem_result = PEMParser.parse_pem_cert(cert)
        return set(pem_result.subject)


    # ct_entry is json-formatted
    # store ct_entry to all target_domain_set files
    def save(self, ct_entry : str, target_domain_set : set):

        # if len(target_domain_set) > 0:
        #     print(target_domain_set)
        for domain in target_domain_set:
            target_file_name = os.path.join(self.save_dir, domain + ".txt")

            # 确保每个文件都有一个独立的锁
            with self.file_dict_lock:
                if target_file_name not in self.file_locks:
                    self.file_locks[target_file_name] = Lock()

            # 加锁写入文件
            with self.file_locks[target_file_name]:
                with open(target_file_name, 'a') as file:
                    json.dump(ct_entry, file, indent=4)
                    file.write('\n')  # 换行符用于分隔每个 JSON 对象

