
'''
    4 - 签发者
    (1) 整体上是否有更换 CA 的倾向
    (2) 在同一天的证书的 CA 情况如何，都使用哪些 CA，哪些 CA 同时使用的最多？
    (3) 相同的 SAN 中更换 CA 的情况如何
'''

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
import ast

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
with open(os.path.join(os.path.dirname(__file__), r"../../../app/data/top-1m.csv"), 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/cert_replica/counting_out_50M.json', 'r') as f:
    json_data = json.load(f)

    _1_ca_sort_by_not_before = {}
    _2_ca_for_each_day = {}
    _3_ca_for_same_san_sort_by_not_before = {}

    for domain, data in json_data.items():
        if data["num"] > 1:

            _1_ca_sort_by_not_before[domain] = {}
            _2_ca_for_each_day[domain] = {}
            _3_ca_for_same_san_sort_by_not_before[domain] = {}

            not_before_to_everything = data['not_before_to_everything']
            subject_set_to_everything = data['subject_set_to_everything']

            # time
            for not_before, certs in not_before_to_everything.items():
                _1_ca_sort_by_not_before[domain][not_before] = list(set(certs["issuer_cn"]))

            _1_ca_sort_by_not_before[domain] = dict(sorted(_1_ca_sort_by_not_before[domain].items(), key=lambda item: item[0]))

            # san
            for san_set, certs in subject_set_to_everything.items():
                _3_ca_for_same_san_sort_by_not_before[domain][san_set] = list(set(certs["issuer_cn"]))


with open("4-1.txt", "w") as file:
    json.dump(_1_ca_sort_by_not_before, file, indent=4, default=custom_serializer)

with open("4-2.txt", "w") as file:
    json.dump(_2_ca_for_each_day, file, indent=4, default=custom_serializer)

with open("4-3.txt", "w") as file:
    json.dump(_3_ca_for_same_san_sort_by_not_before, file, indent=4, default=custom_serializer)


change_ca_times = []
for domain, data in _1_ca_sort_by_not_before.items():

    change_time = -1
    ca_last = []
    for day, ca_set in data.items():
        if ca_set != ca_last:
            change_time += 1
            ca_last = ca_set
    change_ca_times.append(change_time)

# CDF
sorted_y = np.sort(change_ca_times)

# 计算 CDF y 值
cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# 绘制 CDF 曲线图
plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
plt.title('CDF of Change CA Times')
plt.xlabel('Value')
plt.ylabel('CDF')
plt.legend()

plt.savefig('4-1.png', dpi=300, bbox_inches='tight')
plt.show()

