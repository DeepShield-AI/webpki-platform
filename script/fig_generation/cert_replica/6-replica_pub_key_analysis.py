
'''
    6 - Public Keys
    (1)
    (2)

'''

from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import json
import csv
import os
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from datetime import datetime
import base64

# 自定义序列化函数
def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d")
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
    raise TypeError(f"Type {type(obj)} not serializable")

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/cert_replica/counting_out_50M.json', 'r') as f:
    json_data = json.load(f)

    _1_key_overview = {}
    _2_key_for_same_day = {}
    _3_key_for_same_san = {}

    for domain, data in json_data.items():
        if data["num"] > 1:

            _1_key_overview[domain] = {
                "rank" : rank_dict[domain],
                "pub_key" : data["pub_key"]
            }
            _2_key_for_same_day[domain] = {}
            _3_key_for_same_san[domain] = {}

            not_before_to_everything = data['not_before_to_everything']
            subject_set_to_everything = data['subject_set_to_everything']

            # time
            for not_before, certs in not_before_to_everything.items():
                _2_key_for_same_day[domain][not_before] = certs["pub_key_id"]

            # san
            for san_set, certs in subject_set_to_everything.items():
                _3_key_for_same_san[domain][san_set] = certs["pub_key_id"]


with open("6-1.txt", "w") as file:
    json.dump(_1_key_overview, file, indent=4, default=custom_serializer)

with open("6-2.txt", "w") as file:
    json.dump(_2_key_for_same_day, file, indent=4, default=custom_serializer)

with open("6-3.txt", "w") as file:
    json.dump(_3_key_for_same_san, file, indent=4, default=custom_serializer)


# _1_
use_more_than_one_key_set = {}
for domain, data in _1_key_overview.items():
    use_more_than_one_key_set[domain] = []
    for key, num in data["pub_key"].items():
        if num > 1:
            use_more_than_one_key_set[domain].append(key)

# _2_
same_key_date_counting = {}
for domain, data in _2_key_for_same_day.items():
    same_keys = use_more_than_one_key_set[domain]

    for date, keys in data.items():
        for key in keys:
            if key in same_keys:
                if key not in same_key_date_counting:
                    same_key_date_counting[key] = []
                same_key_date_counting[key].append({
                    "domain" : domain,
                    "date" : date
                })

with open("6-2-1.txt", "w") as file:
    json.dump(same_key_date_counting, file, indent=4, default=custom_serializer)

# _3_
same_key_san_counting = {}
for domain, data in _3_key_for_same_san.items():
    same_keys = use_more_than_one_key_set[domain]

    for san, keys in data.items():
        for key in keys:
            if key in same_keys:
                if key not in same_key_san_counting:
                    same_key_san_counting[key] = set()
                same_key_san_counting[key].add(san)

with open("6-3-1.txt", "w") as file:
    json.dump(same_key_san_counting, file, indent=4, default=custom_serializer)
