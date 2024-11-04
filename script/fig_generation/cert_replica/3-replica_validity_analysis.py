
'''
    3 - Validity Period
    (1) 整体情况，更换频率，长度，是否存在 Gap
    (2) 同一天的 证书情况，包括有效期长度
    (3) 同一 SAN 的证书情况，包括更换频率，长度，是否存在 Gap
    (4) Overlap 具体分析，比如 100%时间内都overlap 的证书有多少
'''

from collections import defaultdict, Counter
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

    _1_validity_overview = {}
    _2_validity_for_same_day = {}
    _3_validity_for_same_san = {}
    _4_100_overlap = {}
    _5_timestamp_sequence = {}

    for domain, data in json_data.items():
        if data["num"] > 1:

            _1_validity_overview[domain] = {
                "rank" : rank_dict[domain],
                "valid_period" : data["valid_period"]
            }
            _2_validity_for_same_day[domain] = {}
            _3_validity_for_same_san[domain] = {}
            _4_100_overlap[domain] = 0
            _5_timestamp_sequence[domain] = sorted(data['ct_timestamp'])

            not_before_to_everything = data['not_before_to_everything']
            subject_set_to_everything = data['subject_set_to_everything']

            # time
            for not_before, certs in not_before_to_everything.items():
                _2_validity_for_same_day[domain][not_before] = certs["valid_period"]
                count = Counter(certs["valid_period"])
                for k, v in count.items():
                    _4_100_overlap[domain] += 1

            # san
            for san_set, certs in subject_set_to_everything.items():
                _3_validity_for_same_san[domain][san_set] = certs["valid_period"]


with open("3-1.txt", "w") as file:
    json.dump(_1_validity_overview, file, indent=4, default=custom_serializer)

with open("3-2.txt", "w") as file:
    json.dump(_2_validity_for_same_day, file, indent=4, default=custom_serializer)

with open("3-3.txt", "w") as file:
    json.dump(_3_validity_for_same_san, file, indent=4, default=custom_serializer)

with open("3-4.txt", "w") as file:
    json.dump(_4_100_overlap, file, indent=4, default=custom_serializer)

with open("3-5.txt", "w") as file:
    json.dump(_5_timestamp_sequence, file, indent=4, default=custom_serializer)

# _1_
# 将rank转为整数
for key in _1_validity_overview.keys():
    _1_validity_overview[key]['rank'] = int(_1_validity_overview[key]['rank'])

# 设置 bin 间隔
bin_size = 10000
max_rank = max(d['rank'] for d in _1_validity_overview.values())
bins = np.arange(0, max_rank + bin_size, bin_size)

# 初始化 heatmap 数据结构
heatmap_data = {}

# 填充数据
for entry in _1_validity_overview.values():
    rank_bin = bins[np.digitize(entry['rank'], bins) - 1]
    if rank_bin not in heatmap_data:
        heatmap_data[rank_bin] = {}
    for period, count in entry['valid_period'].items():
        period = int(period)  # 转换为整数
        if period not in heatmap_data[rank_bin]:
            heatmap_data[rank_bin][period] = 0
        heatmap_data[rank_bin][period] += count

# 转换为百分比
for rank_bin in heatmap_data:
    total = sum(heatmap_data[rank_bin].values())
    for period in heatmap_data[rank_bin]:
        heatmap_data[rank_bin][period] /= total

# 构造矩阵
valid_periods = sorted({period for periods in heatmap_data.values() for period in periods})  # 确保排序为整数排序
heatmap_matrix = np.zeros((len(valid_periods), len(bins)))

for i, period in enumerate(valid_periods):
    for j, rank_bin in enumerate(bins):
        heatmap_matrix[i, j] = heatmap_data.get(rank_bin, {}).get(period, 0)

# 绘制热力图
plt.figure(figsize=(10, 8))
ax = sns.heatmap(heatmap_matrix, xticklabels=bins, yticklabels=valid_periods, cmap="magma_r")

# 设置横坐标标签的显示方式（例如每隔5个显示一个）
step = 5
ax.set_xticks(np.arange(0, len(bins), step))
ax.set_xticklabels(bins[::step])

plt.xlabel("Rank Bin")
plt.ylabel("Valid Period")
plt.title("Heatmap of Valid Period Percentage by Rank")
plt.savefig('3-1.png', dpi=300, bbox_inches='tight')
plt.show()

# _2_
more_than_one_periods = {}
overall_reissue_period = []
for domain, data in _2_validity_for_same_day.items():

    # sort data by time
    sorted_data = dict(sorted(data.items(), key=lambda item: item[0]))

    previous_date = None
    for date, valids in sorted_data.items():
        date_in_date_time = datetime.strptime(date, "%Y-%m-%d")

        if previous_date:
            overall_reissue_period.append((date_in_date_time - previous_date).days)
        for i in range(len(valids) - 1):
            overall_reissue_period.append(0)
        previous_date = date_in_date_time

        if len(set(valids)) > 1:
            if date not in more_than_one_periods:
                more_than_one_periods[date] = []
            unique_list = list(set(valids))
            more_than_one_periods[date].append({
                "domain" : domain,
                "valid_periods" : unique_list
            })

with open("3-2-1.txt", "w") as file:
    json.dump(more_than_one_periods, file, indent=4, default=custom_serializer)

# CDF
sorted_y = np.sort(overall_reissue_period)

# 计算 CDF y 值
cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# 绘制 CDF 曲线图
plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
plt.title('CDF of Cert Reissuace')
plt.xlabel('Value')
plt.ylabel('CDF')
plt.legend()

plt.savefig('3-2.png', dpi=300, bbox_inches='tight')
plt.show()

# _3_
more_than_one_periods = {}
for domain, data in _3_validity_for_same_san.items():

    for san, valids in data.items():
        if len(set(valids)) > 1:
            if san not in more_than_one_periods:
                more_than_one_periods[san] = []
            unique_list = list(set(valids))
            more_than_one_periods[san].append({
                "domain" : domain,
                "valid_periods" : unique_list
            })

with open("3-3-1.txt", "w") as file:
    json.dump(more_than_one_periods, file, indent=4, default=custom_serializer)
