
import os
import ast
import csv

# 1 : google.com
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r', encoding='utf-8') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[0]] = row[1]

# google.com  : "000000000"
jarm_dict = {}
with open(r"D:/global_ca_monitor/script/attack/jarm_sabre.csv", 'r', encoding='utf-8') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        jarm_dict[row[0]] = row[1]


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
        # 1 : {self : "000000", num : 5}
        self.output = {}

    def start(self, file_path : str):
        file_path = os.path.join(self.load_dir, file_path)
        with open(file_path, "r", encoding='utf-8') as file:
            print(file_path)
            data = csv.reader(file)
            print(data.line_num)

            for row in data:
                try:
                    actual_list = ast.literal_eval(row[1])
                    for target in actual_list:
                        if target not in self.output:
                            target_domain = rank_dict[target]
                            try:
                                target_jarm = jarm_dict[target_domain]
                                self.output[target] = {
                                    's' : target_jarm,
                                    'n' : 0
                                }
                            except KeyError:
                                self.output[target] = {
                                    's' : "",
                                    'n' : -1
                                }

                        if row[0] in jarm_dict:
                            related_jarm = jarm_dict[row[0]]
                            if related_jarm == self.output[target]['s']:
                                self.output[target]['n'] += 1
                except ValueError:
                    print(row)

    def save(self):
        save_file = os.path.join(self.save_dir, f"6-jarm_hit_{self.log_name}.csv")
        with open(save_file, 'w', encoding='utf-8', newline='') as f:
            print(f"Open {save_file}...")
            writer = csv.writer(f)
            writer.writerow(['Target', 'HitNum'])
            for k, v in self.output.items():
                writer.writerow([k, v['n']])

parser = RelatedDomains(
    log_name = "sabre",
    load_dir = r'D:/global_ca_monitor/script/attack/',
    save_dir = r'./'
)
# parser.start("nimbus_test_100.csv")
# parser.start("related_domains_nimbus1.csv")
# parser.start("related_domains_nimbus2.csv")
parser.start("related_domains_sabre.csv")
parser.save()
