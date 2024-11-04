
import numpy as np
import matplotlib.pyplot as plt
import json
import csv

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'1.txt', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

    count_dict = {}
    for domain, data in json_data.items():
        if len(data) > 0:
            count_dict[domain] = len(data)

# CDF
sorted_y = np.sort(list(count_dict.values()))

# 计算 CDF y 值
cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# 绘制 CDF 曲线图
plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
plt.title('CDF of leakage counting')
plt.xscale('log')
plt.xlabel('Value')
plt.ylabel('CDF')
plt.legend()

plt.savefig('1-1-1.png', dpi=300, bbox_inches='tight')
plt.show()

rank_count_dict = {}
for domain, count in count_dict.items():
    rank_count_dict[rank_dict[domain]] = count

# 设置 bin 大小，例如每 1000 个数据为一个 bin
bin_size = 100
binned_x = []
binned_y = []

# 对数据进行 binning
for i in range(0, len(rank_count_dict), bin_size):
    # 获取当前 bin 的数据
    bin_range = list(rank_count_dict.items())[i:i+bin_size]
    
    # 将 bin 的 x 值设为 bin 的起始 rank
    binned_x.append((i + 1) / bin_size)  # 或者用 (i + i + bin_size) / 2 取中值
    
    # 将 bin 的 y 值设为该 bin 内的平均数值
    binned_y.append(sum(num for rank, num in bin_range) / bin_size)

# 创建图形
fig, ax1 = plt.subplots(figsize=(10, 6))

# 绘制柱状图，使用左侧 y 轴
# ax1.bar(binned_x, binned_y, width=1, color='b', label='Counting Growth')
ax1.plot(binned_x, binned_y, color='b', label='Counting Growth')
# ax1.plot(list(rank_count_dict.keys()), list(rank_count_dict.values()), color='b', label='Counting Growth')

ax1.set_xlabel('Rank Index (Binned)')
ax1.set_ylabel('Counting (Log Scale)', color='b')
ax1.set_yscale('log')
ax1.legend(loc='upper left')

# 显示网格
ax1.grid(True, which="both", ls="--")

plt.title('Binned Counting VS Rank')
plt.savefig('1-1-2.png', dpi=300, bbox_inches='tight')
plt.show()
