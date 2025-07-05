
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json
import signal
import threading
import tempfile
import subprocess

from queue import PriorityQueue, Queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.config.analyze_config import ZLINT_PATH
from backend.utils.cert import get_sha256_hex_from_str
from backend.utils.json import custom_serializer
from backend.logger.logger import primary_logger

from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.logger.logger import primary_logger
from backend.utils.json import custom_serializer
from backend.utils.cert import get_sha256_hex_from_str, base64_to_pem
from collections import defaultdict

final_data = defaultdict(int)  # or defaultdict(dict), depending on your needs

key_words = [
    # basic https on 443
    "ho_https",
    "https",
    
    # check tls config
    "weak_tls_version",
    "weak_tls_cipher",

    # check if there are certs
    "no_leaf_cert",

    # check cert structure
    "cert_broke",

    # check 1: if cert sig valid
    "invalid_cert",

    # check 2: if hostname match
    "hostname_mismatch",
    
    # check 3: if expired certs
    "expired_certs",

    # check 4: if self signed
    "self_signed_certs",

    # certs:
    "weak_cipher",
    "weak_hash",
    "long_validity",
    "wrong_version",
    "wrong_key_usage",
    "no_revoke",
    "no_sct"
]

accepted_cipher_list = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
]


class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/CN_GOV_20250324",
            output_file : str = r"/data/zgrab2_scan_data/CN_GOV_20250324_out",
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.queue = Queue()
        self.saver_thread = threading.Thread(target=self.save_results)
        self.saver_thread.start()

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()


    def analyze_single(self, json_obj):
        key_words_set = set()

        try:
            domain = json_obj["domain"]
            data = json_obj["data"]["tls"]

            # Step 1: check if deploy https on port 443
            if data["status"] == "connection-timeout":
                key_words_set.add("no_https")
                self.queue.put(key_words_set)
                return

            elif data["status"] == "success":
                key_words_set.add("https")

                # Step 2: check tls config
                server_hello = data["result"]["handshake_log"]["server_hello"]
                tls_version = server_hello["version"]["name"]

                if tls_version != "TLSv1.2" and tls_version != "TLSv1.3":
                    key_words_set.add("weak_tls_version")

                tls_cipher = server_hello["cipher_suite"]["name"]

                if tls_cipher not in accepted_cipher_list:
                    key_words_set.add("weak_tls_cipher")

                # step 3: check if certs:
                cert = data["result"]["handshake_log"]["server_certificates"]
                leaf = cert["certificate"]
                parsed_leaf : PEMResult = PEMParser.parse_pem_cert(base64_to_pem(leaf["raw"]))
                
                if leaf["raw"] is None:
                    key_words_set.add("no_leaf_cert")
                    self.queue.put(key_words_set)
                    return

                try:
                    chain = cert["chain"]

                    # Step 4: check if cert valid
                    ca_cert :str = chain[0]
                    parsed_ca : PEMResult = PEMParser.parse_pem_cert(base64_to_pem(ca_cert["raw"]))
                    # parsed_chain = [PEMParser.parse_pem_cert(cert) for cert in chain]

                    # step 4.1 cert chain not verified
                    if parsed_leaf.issuer_sha != parsed_ca.subject_sha:
                        key_words_set.add("invalid_cert")
                except KeyError:
                    pass

                # Step 4.2: hostname mismatch
                if domain not in parsed_leaf.subject_cn_list:
                    domain : str
                    wildcard_domain = ".".join(["*"] + domain.split(".")[1:])
                    if wildcard_domain not in parsed_leaf.subject_cn_list:
                        key_words_set.add("hostname_mismatch")

                # step 4.3 check expired certs
                date_obj = datetime.strptime(parsed_leaf.not_after, "%Y-%m-%d-%H-%M-%S")
                now = datetime.now()
                if date_obj < now:
                    key_words_set.add("expired_certs")

                # step 4.4 self-signed certs
                if parsed_leaf.self_signed:
                    key_words_set.add("self_signed_certs")
    
                # step 5 check cert content
                # 5.1 check sig and encrypt alg
                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
                    temp_cert_file.write(base64_to_pem(leaf["raw"]).encode())
                    temp_cert_path = temp_cert_file.name

                try:
                    result = subprocess.run(
                        [
                            ZLINT_PATH,
                            "-includeNames=e_rsa_mod_less_than_2048_bits,e_dsa_shorter_than_2048_bits",
                            temp_cert_path
                            # "-includeNames=e_rsa_mod_less_than_2048_bits,w_rsa_mod_factors_smaller_than_752,e_dsa_shorter_than_2048_bits,e_old_sub_cert_rsa_mod_less_than_1024_bits"
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if result.returncode != 0:
                        raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

                    zlint_output = json.loads(result.stdout)
                    for name, result in zlint_output.items():
                        if result["result"] in ["warn", "error", "fatal"]:
                            key_words_set.add("weak_cipher")

                    # next
                    result = subprocess.run(
                        [
                            ZLINT_PATH,
                            "-includeNames=e_sub_cert_or_sub_ca_using_sha1,e_signature_algorithm_not_supported",
                            temp_cert_path
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if result.returncode != 0:
                        raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

                    zlint_output = json.loads(result.stdout)
                    for name, result in zlint_output.items():
                        if result["result"] in ["warn", "error", "fatal"]:
                            key_words_set.add("weak_hash")

                except RuntimeError as e:
                    print(e)
                    key_words_set.add("cert_broke")

                finally:
                    try:
                        os.unlink(temp_cert_path)
                    except OSError:
                        pass

                # 5.2 validity
                not_before = datetime.strptime(parsed_leaf.not_before, "%Y-%m-%d-%H-%M-%S")
                not_after = datetime.strptime(parsed_leaf.not_after, "%Y-%m-%d-%H-%M-%S")

                validity = (not_after - not_before).days
                if validity > 398:
                    key_words_set.add("long_validity")

                # 5.3 version
                if str(leaf["parsed"]["version"]) != "3":
                    key_words_set.add("wrong_version")

                # 5.4 key usage
                try:
                    if not leaf["parsed"]["extensions"]["extended_key_usage"]["server_auth"]:
                        key_words_set.add("wrong_key_usage")
                except KeyError:
                        key_words_set.add("wrong_key_usage")
                try:
                    if leaf["parsed"]["extensions"]["extended_key_usage"]["certificate_sign"]:
                        key_words_set.add("wrong_key_usage")
                    if leaf["parsed"]["extensions"]["extended_key_usage"]["crl_sign"]:
                        key_words_set.add("wrong_key_usage")
                except:
                    pass

                # 5.4 revoke info
                try:
                    crl = leaf["parsed"]["extensions"]["crl_distribution_points"]
                except KeyError:
                    try:
                        aia = leaf["parsed"]["extensions"]["authority_info_access"]
                    except KeyError:
                        key_words_set.add("no_revoke")

                # 5.5 SCT
                try:
                    crl = leaf["parsed"]["extensions"]["signed_certificate_timestamps"]
                except KeyError:
                    key_words_set.add("no_sct")

        except Exception as e:
            primary_logger.error(e)
        finally:
            self.queue.put(key_words_set)


    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")

                with ThreadPoolExecutor(max_workers=100) as executor:
                    for line in file:
                        # Check if there is signals
                        if self.crtl_c_event.is_set():
                            primary_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        json_obj = json.loads(line.strip())
                        executor.submit(self.analyze_single, json_obj)
                        # executor.submit(self.analyze_single, json_obj).result()

                    # 等待所有线程完成
                    executor.shutdown(wait=True)
                    primary_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.queue.join()

        # Send the poison pill to stop the saver thread
        self.queue.put(None)
        self.saver_thread.join()

    def save_results(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            while True:
                data = self.queue.get()
                if data is None:  # Poison pill to shut down the thread
                    print("Poision detected")
                    break

                # update dict
                for key in data:
                    final_data[key] += 1

                self.queue.task_done()

            try:
                json_str = json.dumps(final_data, ensure_ascii=False, default=custom_serializer)
                f.write(json_str + '\n')
            except Exception as e:
                primary_logger.error(f"Save {data} failed, got exception {e}")
                pass


if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        primary_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    # analyzer = Analyzer(
    #     input_file = r"/data/zgrab2_scan_data/CN_GOV_20250324",
    #     output_file = r"/data/zgrab2_scan_data/CN_GOV_20250324_out",
    # )
    # analyzer = Analyzer(
    #     input_file = r"/data/ip_scan_data/Full_IPv4_20250311_zgrab2",
    #     output_file = r"/data/ip_scan_data/Full_IPv4_20250311_zgrab2_out",
    # )
    analyzer = Analyzer(
        input_file = r"/data/zgrab2_scan_data/CiscoTop1M_20250112",
        output_file = r"/data/zgrab2_scan_data/CiscoTop1M_20250112_out",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
