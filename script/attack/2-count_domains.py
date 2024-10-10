
import os
import ast
import bigjson, csv, json

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
            save_file = os.path.join(self.save_dir, f"related_domains_count_{self.log_name}.csv")
            with open(save_file, 'w', encoding='utf-8', newline='') as f:
                print(f'Reading {file_path}')
                print(f"Open {save_file}...")

                data = csv.reader(file)
                print("Done")

                for row in data:
                    try:
                        actual_list = ast.literal_eval(row[1])
                        for target in actual_list:
                            self.output[target] += 1
                    except ValueError:
                        print(row)

                print("Poision detected")
                writer = csv.writer(f)
                writer.writerow(['Key', 'Value'])
                for k, v in self.output.items():
                    writer.writerow([k, v])

parser = RelatedDomains(
    log_name = "nimbus",
    load_dir = r'D:/global_ca_monitor/script/attack/',
    save_dir = r'./'
)
parser.start("related_domains_nimbus.csv")
