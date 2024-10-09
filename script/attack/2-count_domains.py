
import sys
sys.path.append(r"D:\global_ca_monitor")

import os
import json, csv
from app.utils.json import custom_serializer, split_json_objects


# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]
print(len(list(rank_dict.keys())))

class RelatedDomains():

    def  __init__(
            self,
            log_name = "sabre",
            load_dir = r'D:/global_ca_monitor/data/group_top_domains_sabre',
            save_dir = r'./'
        ) -> None:

        self.log_name = log_name
        self.load_dir = load_dir
        self.save_dir = save_dir
        self.output = {}
        for rank in rank_dict.values():
            self.output[rank] = 0

    def start(self, file_path : str):

        file_path = os.path.join(self.load_dir, file_path)
        with open(file_path, "r", encoding='utf-8') as file:
            print(f'Reading {file_path}')
            data = json.load(file)

        for target_list in data.values():
            for target in target_list:
                self.output[target] += 1

        print("Poision detected")
        save_file = os.path.join(self.save_dir, f"related_domains_count_{self.log_name}")
        with open(save_file, 'w', encoding='utf-8') as f:
            print(f"Open {save_file}...")
            json.dump(self.output, f, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)

parser = RelatedDomains(
    log_name = "nimbus",
    load_dir = r'D:/global_ca_monitor/script/attack/',
    save_dir = r'./'
)
parser.start("related_domains_count_nimbus.json")
