
import re
import os
import json
from typing import Dict
from datetime import datetime
from dataclasses import dataclass

@dataclass
class CertEntry():
    
    sha256 : str
    unique_subject : list
    not_before : datetime
    not_after : datetime

    issuer_cn : str
    issuer_org : str
    key_id : str
    
@dataclass
class ReplicaEntry():
    
    sha256 : str
    matchced_domain : list
    not_before : datetime
    not_after : datetime

    issuer_cn : str
    issuer_org : str
    key_id : str


class ReplicaGroup():

    def __init__(self, reg_name) -> None:
        
        self.reg_domain_name = reg_name
        self.entry_dict : Dict[str, ReplicaEntry] = {}        # key 是实际域名，value 是 ReplicaEntry
        pass


    def add_cert_entry(self, cert_entry : CertEntry, matchced_domain):
        
        replica_entry = ReplicaEntry(
            cert_entry.sha256,
            matchced_domain,
            cert_entry.not_before,
            cert_entry.not_after,
            cert_entry.issuer_cn,
            cert_entry.issuer_org,
            cert_entry.key_id
        )
        if matchced_domain not in self.entry_dict:
            self.entry_dict[matchced_domain] = []
        self.entry_dict[matchced_domain].append(replica_entry)


    def analyze_group(self):
        # The purpose is, find how many cert replicas pair inside this group
        # now, simply compare matched domain and validity period
        count = 0
        
        # 对每个分组内部进行处理
        for domain, group in self.entry_dict.items():
            # 将证书按 not_before 排序
            group.sort(key=lambda x: x.not_before)
            
            # 合并区间并计算交叉的证书对
            merged_start = group[0].not_before
            merged_end = group[0].not_after
            overlap_entries = [group[0]]  # 当前有重叠的证书集合
            
            for i in range(1, len(group)):
                current_entry = group[i]
                
                # 如果当前证书与合并区间有交集，则扩展区间
                if self.validity_has_overlap(current_entry, ReplicaEntry("", [], merged_start, merged_end, '', '', '')):
                    merged_start = min(merged_start, current_entry.not_before)
                    merged_end = max(merged_end, current_entry.not_after)
                    overlap_entries.append(current_entry)
                else:
                    # 在当前区间结束时，计算有多少对证书互相交叉
                    n = len(overlap_entries)
                    count += n * (n - 1) // 2  # 组合数 C(n, 2)
                    
                    # 开始新的区间
                    merged_start = current_entry.not_before
                    merged_end = current_entry.not_after
                    overlap_entries = [current_entry]
            
            # 处理最后一个区间的交叉对
            n = len(overlap_entries)
            count += n * (n - 1) // 2
        
        return count


    def validity_has_overlap(self, entry1, entry2):
        return entry1.not_before <= entry2.not_after and entry1.not_after >= entry2.not_before


class ReplicaCounting():

    def __init__(self) -> None:

        self.load_dir = r'H:/ct_scan_parsed'
        self.counting_dict : Dict[str, ReplicaGroup] = {}        # key 是 ReplicaGroup 的 Reg_expression, value 是 ReplicaGroup 本身
        pass


    def start(self):

        i = 0
        for filename in os.listdir(self.load_dir):
            file_path = os.path.join(self.load_dir, filename)

            if os.path.isfile(file_path):
                with open(file_path, "r") as file:
                    print(f"Open file: {filename}")

                    # read data
                    parsed_data = json.load(file)
                    for cert in parsed_data:
                        cert_entry = self.deal_with_entry(cert)

                        # compare the current cert entry to all keys
                        # and add this entry to (several) groups
                        visited_subject = []
                        for reg_exp, group in self.counting_dict.items():
                            matched_domain = self.compare_entry_with_reg_exp(cert_entry, reg_exp)

                            if matched_domain:
                                group.add_cert_entry(cert_entry, matched_domain)
                                visited_subject.append(matched_domain)
                        
                        # If there are unvisited domains:
                        unvisited_subject = list(set(cert_entry.unique_subject) - set(visited_subject))
                        # print(unvisited_subject)
                        for subject in unvisited_subject:
                            self.counting_dict[subject] = ReplicaGroup(subject)

            i += 1
            if i >= 25:
                break


    def compare_entry_with_reg_exp(self, cert_entry : CertEntry, reg_exp):

        regex_pattern = re.escape(reg_exp).replace(r"\*", r".*")
        for subject in cert_entry.unique_subject:
            if re.match(regex_pattern, subject):
                return subject
        return None


    def deal_with_entry(self, cert):
        
        # First step, zip the subject content
        # if has wildcard names and specific names, we merge them together
        unique_domains = self.filter_unique_domains(cert['subject'])

        # Second step, convert validity to the one that can be compared
        not_before = datetime.strptime(cert['not_before'], "%Y-%m-%d-%H-%M-%S")
        not_after = datetime.strptime(cert['not_after'], "%Y-%m-%d-%H-%M-%S")

        return CertEntry(
            cert['sha256'],
            unique_domains,
            not_before,
            not_after,
            cert['issuer_cn'],
            cert['issuer_org'],
            cert['pub_key_id']
        )


    def filter_unique_domains(self, domains):
        unique_domains = set()  # 用于存储有效域名
        wildcard_domains = set()  # 用于存储通配符域名
        fix_domains = set()

        for domain in domains:
            # 限制层级的正则表达式，匹配最多 4 层域名
            # 要不然域名数量太多了，电脑承受不了
            pattern = r"^([a-zA-Z0-9-]+\.){0,3}[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
            if (not domain) or (not re.match(pattern, domain)):
                continue

            # 检查是否是通配符域名
            if domain.startswith("*."):
                wildcard_domains.add(domain[2:])
                unique_domains.add(domain)
            else:
                fix_domains.add(domain)
        
        # 检查此域名是否已经被通配符域名覆盖
        for domain in fix_domains:
            base_domain = domain.split(".", 1)[1] if "." in domain else domain
            if base_domain not in wildcard_domains:
                unique_domains.add(domain)

        return list(unique_domains)

