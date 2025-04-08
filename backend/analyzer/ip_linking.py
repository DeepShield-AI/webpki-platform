
import os
import json
import threading
from queue import Queue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from ..logger.logger import primary_logger
from ..utils.json import custom_serializer
from ..utils.cert import get_cert_sha256_hex_from_str, base64_to_pem

class IPSCANANALYSIS():

    def __init__(
            self,
            input_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2",
            output_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_simplified",
            output_file_ca : str = r"/data/ip_scan_data/Full_IPv4_20241124_ca_certs"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.output_file_ca = output_file_ca
        self.queue = Queue()
        self.saver_thread = threading.Thread(target=self.save_results)
        self.saver_thread.start()

        self.queue_ca = Queue()
        self.saver_thread_ca = threading.Thread(target=self.save_ca_certs)
        self.saver_thread_ca.start()
        self.ca_sha_256_set = set()

    def analyze_single(self, json_obj):
        ip = json_obj["ip"]

        try:
            cert = json_obj["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            cert_sha_256 = get_cert_sha256_hex_from_str(cert["certificate"]["raw"])
            # chain_sha_256 = [cert_sha_256]
            # not_before = datetime.strptime(cert["certificate"]["parsed"]["validity"]["start"], "%Y-%m-%dT%H:%M:%SZ")
            # not_after = datetime.strptime(cert["certificate"]["parsed"]["validity"]["end"], "%Y-%m-%dT%H:%M:%SZ")

            try:
                org = cert["certificate"]["parsed"]["subject"]["organization"]
            except KeyError:
                org = None

            try:
                country = cert["certificate"]["parsed"]["subject"]["country"]
            except KeyError:
                country = None

            try:
                san = cert["certificate"]["parsed"]["extensions"]["subject_alt_name"]["dns_names"]
            except KeyError:
                san = []

            self.queue.put({
                "ip" : ip,
                "sever_cert_hash" : cert_sha_256,
                "san" : san,
                "org" : org,
                "country" : country
            })

            try:
                chain = cert["chain"]
                chain = [c["raw"] for c in chain]
                self.queue_ca.put(chain)
            except KeyError:
                pass

        except Exception as e:
            # my_logger.debug(f"IP {ip} has no cert received")
            pass

    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")
                for line in file:
                    json_obj = json.loads(line.strip())
                    self.analyze_single(json_obj)

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
                    cert_sha_256 = get_cert_sha256_hex_from_str(cert)
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
