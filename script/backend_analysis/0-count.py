
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json
import threading
import signal
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.logger.logger import my_logger

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110",
            output_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_simplified",
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.queue = Queue()
        self.saver_thread = threading.Thread(target=self.save_results)
        self.saver_thread.start()

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()

    def analyze_single(self, json_obj):
        try:
            cert = json_obj["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            self.queue.put("1")

        except Exception as e:
            # my_logger.debug(f"domain {domain} has no cert received")
            pass

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
        self.queue.join()
        self.queue.put(None)
        self.saver_thread.join()

    def save_results(self):
        count = 0
        while True:
            data = self.queue.get()
            if data is None:  # Poison pill to shut down the thread
                print("Poision detected")
                break
            
            count += 1
            self.queue.task_done()
        print(f"count: {count}")

if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        my_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    analyzer = Analyzer(
        input_file = r"/data/ip_scan_data/Full_IPv4_20250311_zgrab2",
        output_file = r"/data/ip_scan_data/Full_IPv4_20250311_zgrab2_out",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    my_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

# count: 8019620