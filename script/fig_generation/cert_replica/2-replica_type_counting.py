
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
    type_counting_data = {}

    both_ev_and_others = 0

    for domain, data in json_data.items():
        rank = rank_dict[domain]

        if len(data['type'].keys()) > 1:
            both_ev_and_others += 1

        for type, num in data['type'].items():
            if type not in type_counting_data:
                type_counting_data[type] = 0

            type_counting_data[type] += num

print(type_counting_data)
print(both_ev_and_others)
