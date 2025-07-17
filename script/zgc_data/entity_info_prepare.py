
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import csv
import json
import signal
import threading
import tempfile
import subprocess

from urllib.parse import urlparse
from queue import PriorityQueue, Queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from backend.analyzer.cert_analyze_chain import CertChainAnalyzer
from backend.parser.pem_parser import ASN1Parser, PEMResult
from backend.config.analyze_config import ZLINT_PATH
from backend.utils.cert import get_sha256_hex_from_str
from backend.utils.json import custom_serializer
from backend.logger.logger import primary_logger

output_file = open("certs.json", "w", encoding='utf-8')
existing_domain = set()
existing_name = set()

class Analyzer():

    def __init__(
            self,
            _type : str = "政府",
            input_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_0_100000",
            geo_file : str = r"/root/pki-internet-platform/data/school_domains/cn/cn_edu_20241202_loc",
            domain_to_name_file : str = r"/root/pki-internet-platform/data/school_domains/cn/data20230918.csv",
        ) -> None:

        self._type = _type
        self.input_file = input_file
        self.geo_file = geo_file
        self.geo_data = {}

        self.domain_to_name_file = domain_to_name_file
        self.domain_to_name = {}
        self.data_queue = Queue()
        
        self.crtl_c_event = threading.Event()
        self.chain_analyzer = CertChainAnalyzer()
        self.data_save_thread = threading.Thread(target=self.save_results)
        self.data_save_thread.start()

        with open(self.domain_to_name_file, "r", encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            for row in reader:

                if self._type == "高校":
                    # only keep 985 and 211 here
                    tag = row[3]
                    name = row[1]
                    if "985" in tag or "211" in tag:
                        urls = row[4].split(";")
                        urls.reverse()
                    else:
                        urls = []
                elif self._type == "政府":
                    name = row[2]
                    urls = row[3].split(";")
                elif self._type == "央企":
                    name = row[0]
                    urls = row[1].split(";")

                for url in urls:
                    parsed_url = urlparse(url)
                    if parsed_url.netloc:
                        print(parsed_url.netloc, name)
                        self.domain_to_name[parsed_url.netloc] = name
                        # only keep the first
                        break

        with open(self.geo_file, "r", encoding='utf-8') as file:
            for line in file:
                json_obj = json.loads(line.strip())
                if int(json_obj["data"]["status"]) == 1:
                    name = json_obj["name"]
                    geo_codes = json_obj["data"]["geocodes"]

                    for geo_code in geo_codes:
                        region = [
                            geo_code["province"],
                            geo_code["city"],
                            geo_code["district"]
                        ]

                        not_good = False
                        for item in region:
                            if len(item) == 0:
                                not_good = True

                        if not_good:
                            break

                        try:
                            loc = geo_code["location"].split(",")
                        except AttributeError:
                            break

                        lon = loc[0]
                        lat = loc[1]

                        simplified_geo_code = {
                            "latitude": lat,
                            "longitude": lon,
                            "region": region
                        }
                        self.geo_data[name] = simplified_geo_code
                        # TODO: matching
                        break


    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                primary_logger.info(f"Reading file: {self.input_file}")

                with ThreadPoolExecutor(max_workers=10) as executor:
                    for line in file:
                        # Check if there is signals
                        if self.crtl_c_event.is_set():
                            primary_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        json_obj = json.loads(line.strip())
                        # self.analyze_single(json_obj)
                        executor.submit(self.analyze_single, json_obj)
                        # executor.submit(self.analyze_single, json_obj).result()

                    executor.shutdown(wait=True)
                    primary_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.data_queue.join()

        # Send the poison pill to stop the saver thread
        self.data_queue.put(None)
        self.data_save_thread.join()


    def analyze_single(self, json_obj):
        domain = json_obj["destination_host"]
        ip = json_obj["destination_ip"]
        cert_chain = json_obj["cert_chain"]

        # Step 1: check if has cert
        try:
            cert :str = cert_chain[0]
            parsed : PEMResult = ASN1Parser.parse_pem_cert(cert)
            
            # Step 2: parse basic info
            subject_cn = parsed.subject_cn_list[0]
            try:
                issuer_country = parsed.issuer_country.upper()
            except Exception:
                issuer_country = "UN"

            not_before = parsed.not_before.replace("-", "").replace(":", "") + "Z"
            not_after = parsed.not_after.replace("-", "").replace(":", "") + "Z"
            sha256 = get_sha256_hex_from_str(cert)

            # Step 3: check errors
            cert_error = False
            error_info = {
                "algo" : [],
                "deploy" : []
            }

            # 3.1 check expired certs
            date_obj = datetime.strptime(parsed.not_after, "%Y-%m-%d-%H-%M-%S")
            now = datetime.now()
            if date_obj < now:
                cert_error = True
                error_info["deploy"].append("过期")

            # 3.2 check sig and encrypt alg
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
                temp_cert_file.write(cert.encode())
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
                        cert_error = True
                        error_info["algo"].append("密钥长度过短")

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
                        cert_error = True
                        error_info["algo"].append("弱哈希")

            except RuntimeError:
                cert_error = True
                error_info["algo"].append("证书格式错误")
            finally:
                try:
                    os.unlink(temp_cert_path)
                except OSError:
                    pass

            parsed_chain = [ASN1Parser.parse_pem_cert(cert) for cert in cert_chain]

            # 3.3 self-signed certs
            if len(cert_chain) == 1 and parsed.self_signed:
                cert_error = True
                error_info["deploy"].append("自签名")

            # 3.4 cert chain not verified
            if len(parsed_chain) == 1 and parsed.self_signed:
                pass
            else:
                leaf = parsed_chain[0]
                issuer = parsed_chain[1]
                if leaf.issuer_sha != issuer.subject_sha:
                    cert_error = True
                    error_info["deploy"].append("信任链建立失败")

            # if root is None:
            #     cert_error = True
            #     error_info["deploy"].append("信任链建立失败")
            # else:
            #     current = root
            #     for i in range(len(parsed_chain) - 1):
            #         found = False
            #         for cert in parsed_chain:
            #             cert : PEMResult
            #             if cert.issuer_sha == current.subject_sha and cert != root:
            #                 found = True
            #                 current = cert
            #                 break
            #         if not found:
            #             cert_error = True
            #             error_info["deploy"].append("信任链建立失败")
            #             break

            # 3.5 subject cn not match
            if domain not in parsed.subject_cn_list:
                domain : str
                wildcard_domain = ".".join(["*"] + domain.split(".")[1:])
                if wildcard_domain not in parsed.subject_cn_list:
                    cert_error = True
                    error_info["deploy"].append("网站与证书域名不匹配")

            cert_data = {
                "cn" : subject_cn,
                "error" : cert_error,
                "error_info" : error_info,
                "issuer_c" : issuer_country,
                "not_after" : not_after,
                "not_before" : not_before,
                "sha256" : sha256,
            }
            
            info_data = {
                "cert" : cert_data,
                "domain": domain,
                "entity_type": self._type,
                "has_cert": True
            }

        except IndexError:
            info_data = {
                "domain": domain,
                "entity_type": self._type,
                "has_cert": False
            }
        except Exception as e:
            primary_logger.error(e)
            info_data = {
                "domain": domain,
                "entity_type": self._type,
                "has_cert": False
            }
        finally:
            # Final step: append geo_data to here
            try:
                name = self.domain_to_name[domain]
                geo_code = self.geo_data[name]
                info_data["geo"] = geo_code

                final_data = info_data
                final_data["name"] = name
                self.data_queue.put(final_data)
            except KeyError as e:
                primary_logger.error(e)
                pass


    def save_results(self):
        data = {}
        while True:
            entry = self.data_queue.get()

            if entry is None:  # Poison pill to shut down the thread
                primary_logger.info("Poision detected")
                for e in data.values():
                    json_str = json.dumps(e, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                    output_file.write(json_str + '\n')
                self.data_queue.task_done()
                return

            try:
                if entry["domain"] in existing_domain and (not entry["has_cert"]):
                    self.data_queue.task_done()
                    continue
                existing_domain.add(entry["domain"])

                if entry["name"] in existing_name and (not entry["has_cert"]):
                    self.data_queue.task_done()
                    continue
                existing_name.add(entry["name"])

                data[entry["domain"]] = entry

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
        _type = "高校",
        input_file = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_0_100000",
        geo_file = r"/root/pki-internet-platform/data/school_domains/cn/cn_edu_20241202_loc",
        domain_to_name_file = r"/root/pki-internet-platform/data/school_domains/cn/data20230918.csv",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        _type = "政府",
        input_file = r"/data/self_scan_data/CN_GOV_20241203/CN_GOV_20241203_Central_0_100000",
        geo_file = r"/root/pki-internet-platform/data/gov_domains/cn/cn_gov_20241203_loc_central",
        domain_to_name_file = r"/root/pki-internet-platform/data/gov_domains/cn/cn_gov_20241106_map_central",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        _type = "央企",
        input_file = r"/data/self_scan_data/CN_SOE_20241201/CN_SOE_20241201_0_100000",
        geo_file = r"/root/pki-internet-platform/data/enterprise_domains/cn/cn_soe_20241202_loc",
        domain_to_name_file = r"/root/pki-internet-platform/data/enterprise_domains/cn/soe.csv"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
