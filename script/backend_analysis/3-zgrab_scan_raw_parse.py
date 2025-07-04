
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json
import threading
import signal
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.logger.logger import primary_logger
from backend.utils.json import custom_serializer
from backend.utils.cert import get_sha256_hex_from_str, base64_to_pem

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110",
            output_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_simplified",
            output_file_ca : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_certs"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.output_file_ca = output_file_ca
        self.queue = Queue()
        self.saver_thread = threading.Thread(target=self.save_results)
        self.saver_thread.start()

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()

        self.queue_ca = Queue()
        self.saver_thread_ca = threading.Thread(target=self.save_ca_certs)
        self.saver_thread_ca.start()
        self.ca_sha_256_set = set()

    def analyze_single(self, json_obj):
        try:
            cert = json_obj["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            chain = cert["chain"]
            chain = [c["raw"] for c in chain]
            self.queue_ca.put(chain)

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
                            primary_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        json_obj = json.loads(line.strip())
                        executor.submit(self.analyze_single, json_obj)
                        # self.analyze_single(json_obj)

                    # 等待所有线程完成
                    executor.shutdown(wait=True)
                    primary_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.queue.join()
        self.queue_ca.join()

        # Send the poison pill to stop the saver thread
        self.queue.put(None)
        self.queue_ca.put(None)
        self.saver_thread.join()
        self.saver_thread_ca.join()

    def save_results(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            while True:
                data = self.queue.get()
                if data is None:  # Poison pill to shut down the thread
                    print("Poision detected")
                    break

                try:
                    json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                    f.write(json_str + '\n')
                except Exception as e:
                    primary_logger.error(f"Save {data} failed, got exception {e}")
                    pass

                self.queue.task_done()

    def save_ca_certs(self):
        with open(self.output_file_ca, 'w', encoding='utf-8') as f:
            while True:
                data = self.queue_ca.get()
                if data is None:  # Poison pill to shut down the thread
                    print("Poision detected")
                    break

                for cert in data:
                    cert_sha_256 = get_sha256_hex_from_str(cert)
                    if cert_sha_256 in self.ca_sha_256_set:
                        continue
                    self.ca_sha_256_set.add(cert_sha_256)

                    try:
                        pem_data = base64_to_pem(cert)
                        f.write(pem_data + '\n')
                    except Exception as e:
                        primary_logger.error(f"Save {cert} failed, got exception {e}")
                        pass

                self.queue_ca.task_done()

if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        primary_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    analyzer = Analyzer(
        input_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110",
        output_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_simplified",
        output_file_ca = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_certs"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
