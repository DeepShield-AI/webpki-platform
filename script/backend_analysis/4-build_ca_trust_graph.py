
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json
import signal
import threading
from queue import PriorityQueue, Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.logger.logger import primary_logger
from backend.config.analyze_config import TRUST_ROOT_DIR
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.utils.cert import get_cert_sha256_hex_from_str, is_issuer
from backend.utils.json import custom_serializer

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_certs",
            output_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph"
        ) -> None:

        self.input_file = input_file
        self.output_file = open(output_file, "w", encoding='utf-8')
        self.data_queue = Queue()
        self.data = {}
        
        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()

        self.data_save_thread = threading.Thread(target=self.save_results)
        self.data_save_thread.start()

        self.trust_root_store = set()
        self.trust_root_store_sha = set()
        self.untrust_ca_store = []
        self.untrust_root_store = set()
        self.untrust_inter_store = set()

        # load all CCADB trusted root
        for file in os.scandir(TRUST_ROOT_DIR):
            if os.path.isfile(file.path):
                with open(file.path, 'r') as f:
                    trusted_cert_data = f.read()

                certificates = trusted_cert_data.split("-----END CERTIFICATE-----\n")
                for cert in certificates:
                    if "-----BEGIN CERTIFICATE-----" in cert:
                        cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                        self.trust_root_store.add(cert)
                        self.trust_root_store_sha.add(get_cert_sha256_hex_from_str(cert))
                        
                        # add nodes
                        self.data_queue.put({
                            "id": get_cert_sha256_hex_from_str(cert),
                            "type": "trust_root"
                        })
                primary_logger.info(f"Load {len(certificates)} CA certs from {file.path}")

        # prepare untrusted but stored ca certs from scan file
        if os.path.isfile(self.input_file):
            with open(self.input_file, 'r') as f:
                cert_data = f.read()

                certificates = cert_data.split("-----END CERTIFICATE-----\n")
                for cert in certificates:
                    if "-----BEGIN CERTIFICATE-----" in cert:
                        cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾

                        if get_cert_sha256_hex_from_str(cert) not in self.trust_root_store_sha:
                            self.untrust_ca_store.append(cert)


    def analyze(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            for cert in self.untrust_ca_store:
                # Check if there is signals
                if self.crtl_c_event.is_set():
                    primary_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                    break

                executor.submit(self.analyze_single, cert)
                # executor.submit(self.analyze_single, cert).result()

            executor.shutdown(wait=True)
            primary_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.data_queue.join()

        # Send the poison pill to stop the saver thread
        self.data_queue.put(None)
        self.data_save_thread.join()


    def analyze_single(self, cert):

        parsed : PEMResult = PEMParser.parse_pem_cert(cert)
        sha256 = get_cert_sha256_hex_from_str(cert)

        # add node
        node_type = "inter"
        if parsed.self_signed:
            if sha256 in self.trust_root_store_sha:
                node_type = "trust_root"
            else:
                node_type = "untrust_root"

        self.data_queue.put({
            "id": sha256,
            "type": node_type
        })

        # add link
        for issuer_cert in self.untrust_ca_store:
            if is_issuer(cert, issuer_cert):
                issuer_sha256 = get_cert_sha256_hex_from_str(issuer_cert)
                self.data_queue.put({
                    "source": issuer_sha256,
                    "target": sha256,
                    "type": "issue"
                })

        for issuer_cert in self.trust_root_store:
            if is_issuer(cert, issuer_cert):
                issuer_sha256 = get_cert_sha256_hex_from_str(issuer_cert)
                self.data_queue.put({
                    "source": issuer_sha256,
                    "target": sha256,
                    "type": "trust_issue"
                })

    def save_results(self):
        while True:
            entry = self.data_queue.get()

            if entry is None:  # Poison pill to shut down the thread
                print("Poision detected")
                self.data_queue.task_done()
                return

            try:
                json_str = json.dumps(entry, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                self.output_file.write(json_str + '\n')
            except Exception as e:
                primary_logger.error(f"Save {entry} failed, got exception {e}")
                pass
            self.data_queue.task_done()


if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        primary_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    analyzer = Analyzer(
        input_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_certs",
        output_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
