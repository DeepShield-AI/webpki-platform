
import os
import json
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock, Thread
from backend.utils.json import custom_serializer, split_json_objects

class BuildDomainList():

    def  __init__(
            self,
            log_name = "nimbus",
            load_dir = r'D:/global_ca_monitor/data/group_top_domains_nimbus',
            save_dir = r'D:/global_ca_monitor/data/domain_list'
        ) -> None:

        self.log_name = log_name
        self.load_dir = load_dir
        self.save_dir = save_dir
        self.queue = Queue()
        self.visited = set()

        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)

        # @Debug only
        self.lock = Lock()
        self.count = 0
        self.total = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()


    def save_domain(self):
        save_file = os.path.join(self.save_dir, f"domain_list_{self.log_name}")
        with open(save_file, 'w', encoding='utf-8') as f:
            print(f"Open {save_file}...")

            cache = ""
            while True:
                domain_set = self.queue.get()
                if domain_set == "None":  # Poison pill to shut down the thread
                    print("Poision detected")
                    return
                
                # delete wildcard domains, no use during the scan
                # if domain.startswith("*."):
                #     domain = domain[2:]

                for domain in domain_set:
                    if domain in self.visited or domain is None:
                        continue

                    self.visited.add(domain)
                    cache += domain
                    cache += '\n'

                    if len(cache) > 100000:
                        f.write(cache)
                        cache = ""

                self.queue.task_done()


    def scan_thread(self, file_path : str):
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding='utf-8') as file:
                print(f"Reading file: {file_path}")
                data = file.read()

                thread_cache = set()
                for json_str in split_json_objects(data):
                    try:
                        entry = json.loads(json_str)
                        for domain in entry["related"]:
                            if domain not in thread_cache:
                                thread_cache.add(domain)

                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")

                self.queue.put(thread_cache)

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

            self.saver_thread = Thread(target=self.save_domain)
            self.saver_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.saver_thread.start()

            with ThreadPoolExecutor(max_workers=2) as executor:

                for file_entry in os.scandir(self.load_dir):
                    # executor.submit(self.scan_thread, file_entry.path)
                    executor.submit(self.scan_thread, file_entry.path).result()

                executor.shutdown(wait=True)
                print("All threads finished.")

            self.queue.join()
            self.queue.put("None")
            self.saver_thread.join()
