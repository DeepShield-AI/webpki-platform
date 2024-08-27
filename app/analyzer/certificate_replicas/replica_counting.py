
import re
import os
import json

from datetime import datetime
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console
from threading import Lock
from ...parser.pem_parser import PEMParser, PEMResult


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

    def __init__(self) -> None:
        self.load_dir = r'H:/top_1m_collected'
        self.save_dir = r'H:/'
        self.counting_dict = {}

        # @Debug only
        self.lock = Lock()
        self.count = 0
        self.total = 0
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()


    def scan_thread(self, file_name : str):

        fqdn = file_name[:-4]
        file_path = os.path.join(self.load_dir, file_name)
        if os.path.isfile(file_path):

            with open(file_path, "r") as file:
                # print(f"Open file: {file_name}")
                self.counting_dict[fqdn] = {}
                self.counting_dict[fqdn]["num"] = 0
                self.counting_dict[fqdn]["2023_num"] = 0
                self.counting_dict[fqdn]["2024_num"] = 0
                self.counting_dict[fqdn]["wildcard_num"] = 0
                self.counting_dict[fqdn]["wildcard_others"] = []

                self.counting_dict[fqdn]["issuer_cn"] = {}
                self.counting_dict[fqdn]["valid_period"] = {}
                self.counting_dict[fqdn]["type"] = {}

                self.counting_dict[fqdn]["not_before_to_issuer"] = {}

                # read data
                data = file.read()

                # 使用函数分割并解析每个 JSON 对象
                for json_str in self.split_json_objects(data):

                    try:
                        entry = json.loads(json_str)
                        self.counting_dict[fqdn]["num"] += 1

                        pem_parser = PEMParser()
                        leaf_cert_raw = pem_parser.parse_pem_cert(entry['leaf'])

                        if self.check_entry_time(leaf_cert_raw) == 2023:
                            self.counting_dict[fqdn]["2023_num"] += 1
                        else:
                            self.counting_dict[fqdn]["2024_num"] += 1

                        if self.compare_entry_with_fqdn(fqdn, leaf_cert_raw):
                            self.counting_dict[fqdn]["wildcard_num"] += 1
                            self.counting_dict[fqdn]["wildcard_others"] = list(set(leaf_cert_raw.subject))

                        if leaf_cert_raw.issuer_cn not in self.counting_dict[fqdn]["issuer_cn"]:
                            self.counting_dict[fqdn]["issuer_cn"][leaf_cert_raw.issuer_cn] = 0
                        self.counting_dict[fqdn]["issuer_cn"][leaf_cert_raw.issuer_cn] += 1

                        valid_period = self.count_valid_period_days(leaf_cert_raw)
                        if valid_period not in self.counting_dict[fqdn]["valid_period"]:
                            self.counting_dict[fqdn]["valid_period"][valid_period] = 0
                        self.counting_dict[fqdn]["valid_period"][valid_period] += 1

                        if leaf_cert_raw.policy not in self.counting_dict[fqdn]["type"]:
                            self.counting_dict[fqdn]["type"][leaf_cert_raw.policy] = 0
                        self.counting_dict[fqdn]["type"][leaf_cert_raw.policy] += 1

                        if leaf_cert_raw.not_before not in self.counting_dict[fqdn]['not_before_to_issuer']:
                            self.counting_dict[fqdn]['not_before_to_issuer'][leaf_cert_raw.not_before] = []
                        self.counting_dict[fqdn]['not_before_to_issuer'][leaf_cert_raw.not_before].append(leaf_cert_raw.issuer_cn)

                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")

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
            self.total = sum(1 for file_name in os.listdir(self.load_dir) if os.path.isfile(os.path.join(self.load_dir, file_name)))
            self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

            with ThreadPoolExecutor(max_workers=100) as executor:

                for file_name in os.listdir(self.load_dir):
                    executor.submit(self.scan_thread, file_name)
                    # executor.submit(self.scan_thread, file_name).result()
 
                executor.shutdown(wait=True)
                print("All threads finished.")

            with open(os.path.join(self.save_dir, 'counting_out.json'), 'w') as f:
                json.dump(self.counting_dict, f, indent=4)


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


    def compare_entry_with_fqdn(self, fqdn : str, cert_entry : PEMResult) -> bool:

        for subject in cert_entry.subject:
            if subject.startswith("*."):
                regex_pattern = re.escape(subject).replace(r"\*", r".*")
                if re.match(regex_pattern, fqdn):
                    return True
        return False


    def compare_entry_with_reg_exp(self, cert_entry : PEMResult, reg_exp : str) -> str:

        regex_pattern = re.escape(reg_exp).replace(r"\*", r".*")
        for subject in cert_entry.subject:
            if re.match(regex_pattern, subject):
                return subject
        return None


    def check_entry_time(self, cert_entry : PEMResult) -> int:

        not_before = datetime.strptime(cert_entry.not_before, "%Y-%m-%d-%H-%M-%S")
        not_after = datetime.strptime(cert_entry.not_after, "%Y-%m-%d-%H-%M-%S")

        if not_before >= datetime(2024, 1, 1, 0, 0, 0):
            return 2024
        else:
            return 2023


    def count_valid_period_days(self, cert_entry : PEMResult) -> int:

        not_before = datetime.strptime(cert_entry.not_before, "%Y-%m-%d-%H-%M-%S")
        not_after = datetime.strptime(cert_entry.not_after, "%Y-%m-%d-%H-%M-%S")
        
        return (not_after - not_before).days


    # def filter_unique_domains(self, domains):
    #     unique_domains = set()  # 用于存储有效域名
    #     wildcard_domains = set()  # 用于存储通配符域名
    #     fix_domains = set()

    #     for domain in domains:
    #         # 限制层级的正则表达式，匹配最多 4 层域名
    #         # 要不然域名数量太多了，电脑承受不了
    #         pattern = r"^([a-zA-Z0-9-]+\.){0,3}[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
    #         if (not domain) or (not re.match(pattern, domain)):
    #             continue

    #         # 检查是否是通配符域名
    #         if domain.startswith("*."):
    #             wildcard_domains.add(domain[2:])
    #             unique_domains.add(domain)
    #         else:
    #             fix_domains.add(domain)
        
    #     # 检查此域名是否已经被通配符域名覆盖
    #     for domain in fix_domains:
    #         base_domain = domain.split(".", 1)[1] if "." in domain else domain
    #         if base_domain not in wildcard_domains:
    #             unique_domains.add(domain)

    #     return list(unique_domains)

