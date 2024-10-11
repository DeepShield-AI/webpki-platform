
import os
import ast
import csv

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

    def start(self, file_path : str):
        file_path = os.path.join(self.load_dir, file_path)
        with open(file_path, "r", encoding='utf-8') as file:
            print(f'Reading {file_path}')
            data = csv.reader(file)
            print("Done")

            count = 0
            for row in data:
                try:
                    if int(row[1]) > 0:
                        count += 1
                except ValueError:
                    continue
            print(f"Count: {count}")

parser = RelatedDomains(
    log_name = "nimbus",
    load_dir = r'D:/global_ca_monitor/script/attack/',
    save_dir = r'./'
)
parser.start("related_domains_count_sabre.csv")
# parser.start("related_domains_count_sabre.csv")
