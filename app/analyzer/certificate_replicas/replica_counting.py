
'''
    Third step, read those merged large files and analyze data,
    output json data as we want
'''

import re
import os
import json
import base64
import hashlib

from datetime import datetime, timezone
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock
from ...utils.json import custom_serializer

@dataclass
class CertEntry():
    
    sha256 : str
    unique_subject : list
    not_before : datetime
    not_after : datetime

    issuer_cn : str
    issuer_org : str
    key_id : str
    

class ReplicaCounting():

    def  __init__(
            self,
            load_dir = r'D:/global_ca_monitor/data/cert_replica',
            save_dir = r'D:/global_ca_monitor/data/cert_replica'
        ) -> None:

        self.load_dir = load_dir
        self.save_dir = save_dir
        self.counting_dict = {}

        # @Debug only
        self.lock = Lock()
        self.count = 0
        self.total = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()


    def scan_thread(self, file_name : str):

        file_path = os.path.join(self.load_dir, file_name)

        print(f"Open file: {file_name}")
        with open(file_path, "r") as file:
            # read data
            data = json.load(file)

            for fqdn, cert_list in data.items():

                self.counting_dict[fqdn] = {}
                self.counting_dict[fqdn]["num"] = 0
                self.counting_dict[fqdn]["2023_num"] = 0
                self.counting_dict[fqdn]["2024_num"] = 0

                self.counting_dict[fqdn]["wildcard_num"] = 0
                self.counting_dict[fqdn]["wildcard_others"] = []

                self.counting_dict[fqdn]["cert_type"] = {}
                self.counting_dict[fqdn]["issuer_cn"] = {}

                self.counting_dict[fqdn]["gap"] = {}
                self.counting_dict[fqdn]["overlap"] = {}
                self.counting_dict[fqdn]["valid_period"] = {}

                self.counting_dict[fqdn]["pub_key"] = {}
                self.counting_dict[fqdn]["pub_key_alg"] = {}

                self.counting_dict[fqdn]["sig_alg"] = {}
                self.counting_dict[fqdn]["zlint"] = {}

                self.counting_dict[fqdn]["not_before_to_everything"] = {}
                self.counting_dict[fqdn]["subject_set_to_everything"] = {}


                # 使用函数分割并解析每个 JSON 对象
                for entry in cert_list:
                    cert_entry = entry["tbs_certificate"]

                    try:
                        self.counting_dict[fqdn]["num"] += 1

                        if self.check_entry_time(cert_entry) == 2023:
                            self.counting_dict[fqdn]["2023_num"] += 1
                        else:
                            self.counting_dict[fqdn]["2024_num"] += 1

                        if self.compare_entry_with_fqdn(fqdn, cert_entry):
                            self.counting_dict[fqdn]["wildcard_num"] += 1
                            self.counting_dict[fqdn]["wildcard_others"] = list(self.filter_unique_domains(cert_entry))

                        for extension in cert_entry["extensions"]:
                            if extension["extn_id"] == "certificate_policies":
                                policy = extension["extn_value"][0]["policy_identifier"]
                                if policy not in self.counting_dict[fqdn]["cert_type"]:
                                    self.counting_dict[fqdn]["cert_type"][policy] = 0
                                self.counting_dict[fqdn]["cert_type"][policy] += 1

                        issuer_cn = cert_entry["issuer"]["common_name"]
                        if issuer_cn not in self.counting_dict[fqdn]["issuer_cn"]:
                            self.counting_dict[fqdn]["issuer_cn"][issuer_cn] = 0
                        self.counting_dict[fqdn]["issuer_cn"][issuer_cn] += 1

                        # missing gap and overlap here

                        valid_period = self.count_valid_period_days(cert_entry)
                        if valid_period not in self.counting_dict[fqdn]["valid_period"]:
                            self.counting_dict[fqdn]["valid_period"][valid_period] = 0
                        self.counting_dict[fqdn]["valid_period"][valid_period] += 1

                        pub_key_alg = cert_entry['subject_public_key_info']['algorithm']['algorithm']
                        if pub_key_alg == 'rsa':
                            mod = cert_entry['subject_public_key_info']['public_key']['modulus']
                            key_length = (mod.bit_length() + 7) // 8
                            key_id = hashlib.sha1(mod.to_bytes(key_length)).digest().hex()

                        elif pub_key_alg == 'ec':
                            key = cert_entry['subject_public_key_info']['public_key']
                            key_length = len(key)
                            key_id = hashlib.sha1(key.encode()).digest().hex()
                        else:
                            key_length = 0
                            key_id = 'NULL'

                        pub_key_alg = pub_key_alg + "_" + str(key_length)
                        if pub_key_alg not in self.counting_dict[fqdn]["pub_key_alg"]:
                            self.counting_dict[fqdn]["pub_key_alg"][pub_key_alg] = 0
                        self.counting_dict[fqdn]["pub_key_alg"][pub_key_alg] += 1

                        if key_id not in self.counting_dict[fqdn]["pub_key"]:
                            self.counting_dict[fqdn]["pub_key"][key_id] = 0
                        self.counting_dict[fqdn]["pub_key"][key_id] += 1

                        # missing zlint and sig_alg here

                        # must be ordered list
                        ordered_subject_set = sorted(self.filter_unique_domains(cert_entry))
                        not_before =  datetime.fromisoformat(cert_entry['validity']['not_before']).strftime("%Y-%m-%d")

                        if not_before not in self.counting_dict[fqdn]['not_before_to_everything']:
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before] = {}

                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["cert_type"] = []
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["issuer_cn"] = []
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["pub_key_id"] = []
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["pub_key_alg"] = []
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["subject_list"] = []
                            self.counting_dict[fqdn]['not_before_to_everything'][not_before]["valid_period"] = []

                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["cert_type"].append(policy)
                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["issuer_cn"].append(issuer_cn)
                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["pub_key_id"].append(key_id)
                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["pub_key_alg"].append(pub_key_alg)
                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["subject_list"].append(ordered_subject_set)
                        self.counting_dict[fqdn]['not_before_to_everything'][not_before]["valid_period"].append(valid_period)

                        ordered_subject_set = str(ordered_subject_set)
                        if ordered_subject_set not in self.counting_dict[fqdn]['subject_set_to_everything']:
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set] = {}

                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["cert_type"] = []
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["issuer_cn"] = []
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["pub_key_id"] = []
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["pub_key_alg"] = []
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["valid_period"] = []
                            self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["not_before"] = []

                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["cert_type"].append(policy)
                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["issuer_cn"].append(issuer_cn)
                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["pub_key_id"].append(key_id)
                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["pub_key_alg"].append(pub_key_alg)
                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["valid_period"].append(valid_period)
                        self.counting_dict[fqdn]['subject_set_to_everything'][ordered_subject_set]["not_before"].append(not_before)

                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")
    
        print(f"Finish file: {file_name}")

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
            file_name_list = os.listdir(self.load_dir)
            valid_name_list = []
            for file_name in file_name_list:
                if file_name.startswith("total"):
                    valid_name_list.append(file_name)

            self.total = len(valid_name_list)
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)
            with ThreadPoolExecutor(max_workers=10) as executor:

                for file_name in valid_name_list:
                    # executor.submit(self.scan_thread, file_name)
                    executor.submit(self.scan_thread, file_name).result()

                executor.shutdown(wait=True)
                print(f"All threads finished.")

                with open(os.path.join(self.save_dir, f'counting_out_50M.json'), 'w') as f:
                    json.dump(self.counting_dict, f, indent=4, default=custom_serializer)


    def split_json_objects(self, data):
        json_objects = []
        brace_count = 0
        json_str = ""

        for char in data:
            json_str += char

            # 计算花括号的数量来判断 JSON 对象是否完整
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1

            # 当 brace_count 为 0 时，说明一个 JSON 对象已完整
            if brace_count == 0 and json_str.strip():
                json_objects.append(json_str.strip())
                json_str = ""

        return json_objects


    def compare_entry_with_fqdn(self, fqdn : str, cert_entry : str) -> bool:

        for subject in self.filter_unique_domains(cert_entry):
            if subject.startswith("*."):
                regex_pattern = re.escape(subject).replace(r"\*", r".*")
                if re.match(regex_pattern, fqdn):
                    return True
        return False


    def compare_entry_with_reg_exp(self, cert_entry : str, reg_exp : str) -> str:

        regex_pattern = re.escape(reg_exp).replace(r"\*", r".*")
        for subject in self.filter_unique_domains(cert_entry):
            if re.match(regex_pattern, subject):
                return subject
        return None


    def check_entry_time(self, cert_entry : str) -> int:

        not_before = datetime.fromisoformat(cert_entry['validity']['not_before'])
        not_after = datetime.fromisoformat(cert_entry['validity']['not_after'])

        if not_before >= datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc):
            return 2024
        else:
            return 2023


    def count_valid_period_days(self, cert_entry : str) -> int:

        not_before = datetime.fromisoformat(cert_entry['validity']['not_before'])
        not_after = datetime.fromisoformat(cert_entry['validity']['not_after'])
        
        return (not_after - not_before).days


    def filter_unique_domains(self, cert_entry : str):

        subject = [cert_entry['subject']['common_name']]
        for extension in cert_entry["extensions"]:
            if extension["extn_id"] == "subject_alt_name":
                subject += extension["extn_value"]

        return set(subject)
    
        