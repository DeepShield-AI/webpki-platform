
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json
import signal
import threading
import subprocess

from datetime import datetime, timezone
from queue import PriorityQueue, Queue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.dialects.mysql import insert

from app import db, app
from app.utils.cert import get_cert_sha256_hex_from_str
from app.utils.type import ScanType, ScanStatusType
from app.utils.json import custom_serializer
from app.utils.network import resolve_host_dns
from app.logger.logger import my_logger

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_0_100000",
            output_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_result"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.data_queue = Queue()
        self.data = {}
        
        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()

        self.data_save_thread = threading.Thread(target=self.save_results)
        self.data_save_thread.start()

    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")

                with ThreadPoolExecutor(max_workers=10) as executor:
                    for line in file:
                        # Check if there is signals
                        if self.crtl_c_event.is_set():
                            my_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        json_obj = json.loads(line.strip())
                        executor.submit(self.analyze_single, json_obj)
                        # self.analyze_single(json_obj)

                    # 等待所有线程完成
                    executor.shutdown(wait=True)
                    my_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.data_queue.join()

        # Send the poison pill to stop the saver thread
        self.data_queue.put(None)
        self.data_save_thread.join()

        # my_logger.info(f"{self.data}")
        with open(self.output_file, "w", encoding='utf-8') as file:
            json.dump(self.data, file, indent=4)

        deployed = 0
        deployed_all = 0
        consistant = 0
        for key, value in self.data.items():
            if value["deploy"]: deployed += 1
            if value["deploy_all"]: deployed_all += 1
            if value["deploy"] and value["consistant"]: consistant += 1
            
        my_logger.info(f"Result for {self.input_file}:")
        my_logger.info(f"Deployed: {deployed}")
        my_logger.info(f"Deployed all: {deployed_all}")
        my_logger.info(f"Consistant: {consistant}")

    def analyze_single(self, json_obj):
        domain = json_obj["destination_host"]
        cert_chain = json_obj["cert_chain"]

        try:
            sha256 = get_cert_sha256_hex_from_str(cert_chain[0])
        except IndexError:
            sha256 = None

        self.data_queue.put({
            "domain" : domain,
            "sha256" : sha256
        })

    def save_results(self):
        while True:
            entry = self.data_queue.get()

            if entry is None:  # Poison pill to shut down the thread
                print("Poision detected")
                return

            if entry["domain"] not in self.data:
                if entry["sha256"]:
                    self.data[entry["domain"]] = {
                        "deploy" : True,
                        "deploy_all" : True,
                        "consistant" : True,
                        "current_sha256" : entry["sha256"]
                    }
                else:
                    self.data[entry["domain"]] = {
                        "deploy" : False,
                        "deploy_all" : False,
                        "consistant" : True,
                        "current_sha256" : entry["sha256"]
                    }
            else:
                if entry["sha256"] != self.data[entry["domain"]]["current_sha256"]:
                    self.data[entry["domain"]]["consistant"] = False
                if entry["sha256"]:
                    self.data[entry["domain"]]["deploy"] = True
                if not entry["sha256"]:
                    self.data[entry["domain"]]["deploy_all"] = False

            self.data_queue.task_done()

if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        my_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    analyzer = Analyzer(
        input_file = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_0_100000",
        output_file = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_result_1"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    my_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        input_file = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_0_100000",
        output_file = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_result_1"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    my_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        input_file = r"/data/self_scan_data/CN_SOE_20241201/CN_SOE_20241201_0_100000",
        output_file = r"/data/self_scan_data/CN_SOE_20241201/CN_SOE_20241201_result_1"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    my_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
