
import os
import json
import time
import hashlib
import threading

from queue import Queue
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID

class CompressScanContent():

    def  __init__(
            self,
            load_dir = r'H:/sabre2024h1',
            save_dir = r'H:/sabre2024h1_compressed'
        ) -> None:

        self.load_dir = load_dir
        self.save_dir = save_dir

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        self.queue = Queue()
        self.ca_sha_256_set_lock = Lock()
        self.ca_sha_256_set = set()

        # @Debug only
        self.count_lock = Lock()
        self.total = 0
        self.count = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()

        # read old unique_ca_certs file and compute all the existing sha256
        self.unique_ca_certs_file = os.path.join(self.save_dir, "unique_ca_certs")
        with open(self.unique_ca_certs_file, 'r') as f:
            cert_data = f.read()

            certificates = cert_data.split("-----END CERTIFICATE-----\n")
            for cert in certificates:
                if "-----BEGIN CERTIFICATE-----" in cert:
                    cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                    cert_sha256 = self.compute_sha256(cert)
                    self.ca_sha_256_set.add(cert_sha256)


    def compute_sha256(self, cert):
        return hashlib.sha256(cert.encode('utf-8')).hexdigest()


    def scan_thread(self, load_file, save_file):
        with open(load_file, 'r') as f:
            data = json.load(f)

        for key, value in data.items():
            new_chain = []
            for cert in value.get("chain", []):
                sha256_hash = self.compute_sha256(cert)
                new_chain.append(sha256_hash)
                if sha256_hash not in self.ca_sha_256_set:
                    with self.ca_sha_256_set_lock:
                        self.ca_sha_256_set.add(sha256_hash)
                        self.queue.put(cert)
            
            # Replace the chain with its SHA-256 hash
            value["chain"] = new_chain

        with open(save_file, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"Load file: {load_file}")
        with self.count_lock:
            self.count += 1
        self.progress.update(self.progress_task, description=f"[green]Completed: {self.count}")
        self.progress.advance(self.progress_task)


    def save_ca_certs(self):
        while True:
            ca_cert = self.queue.get()
            if ca_cert is None:  # Poison pill to shut down the thread
                print("Poision detected")
                break
            with open(self.unique_ca_certs_file, 'a') as f:
                f.write(ca_cert)
            self.queue.task_done()


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:

            # how many files here?
            print(f"Starting compression on {self.load_dir}...")
            '''
                Use scandir instead of listdir to save time and space
                scandir method returns an iterator, not a list
                so do care that after "for i in scandir()"
                there will be no element insider the iterator
            '''
            file_entries = os.scandir(self.load_dir)
            self.total = sum(1 for file_entry in file_entries if os.path.isfile(file_entry.path))
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

            # Start the thread that saves processed data from the queue
            self.saver_thread = threading.Thread(target=self.save_ca_certs)
            self.saver_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.saver_thread.start()

            # 5 is a good number for large file IO access
            file_entries = os.scandir(self.load_dir)
            with ThreadPoolExecutor(max_workers=25) as executor:
                for file_entry in file_entries:

                    # @debug only
                    if self.count < 69493:
                    # if self.count < 1840:
                        self.count += 1
                        self.progress.update(self.progress_task, description=f"[green]Completed: {self.count} [red]Total: {self.total}")
                        self.progress.advance(self.progress_task)
                        # print(f"Skip {self.count} files~")
                        continue

                    load_file_path = file_entry.path
                    save_file_path = os.path.join(self.save_dir, file_entry.name)

                    if os.path.isfile(load_file_path):
                        executor.submit(self.scan_thread, load_file_path, save_file_path)
 
                executor.shutdown(wait=True)
                print("All threads finished.")
            
            # Wait for all elements in queue to be handled
            self.queue.join()

            # Send the poison pill to stop the saver thread
            self.queue.put(None)
            self.saver_thread.join()
