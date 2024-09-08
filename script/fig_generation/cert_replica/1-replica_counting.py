
'''
    1 - 只统计证书副本的数量，包括：
    (1) 我们的数据中存在多少 Top-1M 网站
    (2) 每个网站发现了多少证书副本，有多少网站存在证书副本的现象，这些副本的有效时间在那些范围内
    (3) 网站的证书副本是否和 Top Rank 有关系
    (4) 有哪些网站的证书副本额外的多，超过 100 个，从这里面能发现什么？
'''

import numpy as np
import matplotlib.pyplot as plt
import json
import csv
import os

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/cert_replica/counting_out_50M.json', 'r') as f:
    json_data = json.load(f)
    print(f"(1) Total amount of sites: {len(json_data.keys())}")

    _1_total_certs = 0
    _2_cert_replica_data_count = 0
    _3_rank_compare_data = {}
    _4_many_replica_domains = []

    for domain, data in json_data.items():

        _1_total_certs += data['num']

        if data["num"] > 1:
            # has cert replicas
            _2_cert_replica_data_count += 1

        rank = rank_dict[domain]
        _3_rank_compare_data[int(rank)] = data["num"]

        if data["num"] >= 100:
            _4_many_replica_domains.append(domain)

print(f"(1) Total amount of certs in top-1m: {_1_total_certs}")
print(f"(2) Total amount of sites with certificate replicas: {_2_cert_replica_data_count}")

# 对 counting_data 按 rank 排序
_3_rank_compare_data = dict(sorted(_3_rank_compare_data.items()))

# 设置 bin 大小，例如每 1000 个数据为一个 bin
bin_size = 100
binned_x = []
binned_y = []

# 对数据进行 binning
for i in range(0, len(_3_rank_compare_data), bin_size):
    # 获取当前 bin 的数据
    bin_range = list(_3_rank_compare_data.items())[i:i+bin_size]
    
    # 将 bin 的 x 值设为 bin 的起始 rank
    binned_x.append((i + 1) / bin_size)  # 或者用 (i + i + bin_size) / 2 取中值
    
    # 将 bin 的 y 值设为该 bin 内的平均数值
    binned_y.append(sum(num for rank, num in bin_range) / bin_size)

# 创建图形
fig, ax1 = plt.subplots(figsize=(10, 6))

# 绘制柱状图，使用左侧 y 轴
# ax1.bar(binned_x, binned_y, width=1, color='b', label='Counting Growth')
ax1.plot(binned_x, binned_y, color='b', label='Counting Growth')

ax1.set_xlabel('Rank Index (Binned)')
ax1.set_ylabel('Counting (Log Scale)', color='b')
ax1.set_yscale('log')
ax1.legend(loc='upper left')

# 创建第二个 y 轴，绘制 CDF 图
# ax2 = ax1.twinx()
# ax2.plot(x, cdf_data, marker='o', color='r', label='CDF', linestyle='--')
# ax2.set_ylabel('CDF', color='r')
# ax2.set_ylim(0, 1)  # CDF 的范围为 [0, 1]
# ax2.legend(loc='upper right')

# 显示网格
ax1.grid(True, which="both", ls="--")

plt.title('Binned Counting VS Rank')
plt.savefig('1-3-1.png', dpi=300, bbox_inches='tight')
plt.show()


# CDF
# 对 binned_y 数据进行排序
sorted_y = np.sort(binned_y)

# 计算 CDF y 值
cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# 绘制 CDF 曲线图
plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
plt.title('CDF of binned_y')
plt.xlabel('Value')
plt.ylabel('CDF')
plt.legend()

plt.savefig('1-3-2.png', dpi=300, bbox_inches='tight')
plt.show()


with open("1-4.txt", "w") as file:
    json.dump(_4_many_replica_domains, file, indent=4)

