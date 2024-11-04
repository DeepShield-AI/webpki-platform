
import json
import csv
import os
import sys
sys.path.append(r"D:\global_ca_monitor")
from app.utils.json import custom_serializer

rank_dict = {}
top_domain_related = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]
        top_domain_related[row[1]] = {
            "single" : 0,
            "total" : 0
        }

load_dir = r'D:/global_ca_monitor/data/cert_replica'
for file_entry in os.scandir(load_dir):

    print(f"Open {file_entry}")
    with open(file_entry.path, 'r', encoding='utf-8') as f:
        for json_str in f.readlines():
            entry = json.loads(json_str)

            if len(entry["san"]) == 1:
                subject = entry["san"][0]
                if subject in top_domain_related:
                    top_domain_related[subject]["single"] += 1
                    top_domain_related[subject]["total"] += 1
            else:
                for subject in entry["san"]:
                    if subject in top_domain_related:
                        top_domain_related[subject]["total"] += 1

with open("3.txt", "w", encoding='utf-8') as file:
    json.dump(top_domain_related, file, indent=4, default=custom_serializer)
