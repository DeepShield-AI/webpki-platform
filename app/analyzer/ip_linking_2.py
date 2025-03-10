
import os
import csv, json
from app.utils.domain import group_by_root_domain

class IPCERTMATCH():

    def __init__(
            self,
            input_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_simplified",
            output_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_domain_to_ip",
            output_file2 : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_country_to_ip",
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.output_file2 = output_file2
        self.cert_to_ip = {}
        self.org_to_ip = {}
        self.country_to_ip = {}
        self.domain_to_ip = {}

    def analyze_single(self, json_obj):
        ip = json_obj["ip"]

        # server_cert_hash = json_obj["sever_cert_hash"]
        # if server_cert_hash not in self.cert_to_ip:
        #     self.cert_to_ip[server_cert_hash] = []
        # self.cert_to_ip[server_cert_hash].append(ip)

        # org = json_obj["org"]
        # if org:
        #     if org[0] not in self.org_to_ip:
        #         self.org_to_ip[org[0]] = []
        #     self.org_to_ip[org[0]].append(ip)

        # country = json_obj["country"]
        # if country:
        #     if country[0] not in self.country_to_ip:
        #         self.country_to_ip[country[0]] = []
        #     self.country_to_ip[country[0]].append(ip)

        san = json_obj["san"]
        root_domains = group_by_root_domain(san)

        for domain in root_domains:
            if domain not in self.domain_to_ip:
                self.domain_to_ip[domain] = []
            self.domain_to_ip[domain].append(ip)


    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")
                for line in file:
                    json_obj = json.loads(line.strip())
                    self.analyze_single(json_obj)

        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            for cert, ips in self.domain_to_ip.items():
                writer = csv.writer(f, escapechar='\\')
                writer.writerow([cert] + ips)
        
        # with open(self.output_file2, 'w', newline='', encoding='utf-8') as f:
        #     for cert, ips in self.country_to_ip.items():
        #         writer = csv.writer(f, escapechar='\\')
        #         writer.writerow([cert] + ips)
