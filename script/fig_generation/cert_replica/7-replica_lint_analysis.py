
import numpy as np
import matplotlib.pyplot as plt
import json
import csv
import os

# 读取排名数据
rank_dict = {}
with open(os.path.join(os.path.dirname(__file__), r"../../../app/data/top-1m.csv"), 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/counting_out.json', 'r') as f:
    json_data = json.load(f)

    wildcard_total = 0
    type_counting_data = {}

    for domain, data in json_data.items():
        rank = rank_dict[domain]

        wildcard_total += data['wildcard_num']

        for other_domain in data['wildcard_others']:
            pass

print(wildcard_total)
