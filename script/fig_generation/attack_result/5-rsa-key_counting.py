
import json
import csv
import os
import sys
sys.path.append(r"D:\global_ca_monitor")
from backend.utils.json import custom_serializer

rank_dict = {}
top_domain_related = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]
        top_domain_related[row[1]] = []

load_dir = r'D:/global_ca_monitor/data/cert_replica'
for file_entry in os.scandir(load_dir):

    print(f"Open {file_entry}")
    with open(file_entry.path, 'r', encoding='utf-8') as f:
        for json_str in f.readlines():
            entry = json.loads(json_str)

            for subject in entry["san"]:
                if subject in top_domain_related:
                    if entry["pub_key_alg"] == "rsa":
                        top_domain_related[subject].append(entry["pub_key"]["modulus"])

with open("5.txt", "w", encoding='utf-8') as file:
    json.dump(top_domain_related, file, indent=4, default=custom_serializer)
