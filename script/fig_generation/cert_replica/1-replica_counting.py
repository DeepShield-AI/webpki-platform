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
    counting_data = {}

    print(len(json_data.keys()))

    for domain, num in json_data.items():
        rank = rank_dict[domain]
        counting_data[int(rank)] = num  # 确保 rank 是整数

# 对 counting_data 按 rank 排序
counting_data = dict(sorted(counting_data.items()))
# print(counting_data)

# 设置 bin 大小，例如每 1000 个数据为一个 bin
bin_size = 10
binned_x = []
binned_y = []

# 对数据进行 binning
for i in range(0, len(counting_data), bin_size):
    # 获取当前 bin 的数据
    bin_range = list(counting_data.items())[i:i+bin_size]
    # print(bin_range)
    
    # 将 bin 的 x 值设为 bin 的起始 rank
    binned_x.append((i + 1) / bin_size)  # 或者用 (i + i + bin_size) / 2 取中值
    
    # 将 bin 的 y 值设为该 bin 内的总和
    binned_y.append(sum(num for rank, num in bin_range) / bin_size)

print(len(binned_x))

# 创建图形
fig, ax1 = plt.subplots(figsize=(10, 6))

# 绘制柱状图，使用左侧 y 轴
ax1.bar(binned_x, binned_y, width=1, color='b', label='Counting Growth')
ax1.set_xlabel('Rank Index (Binned)')
ax1.set_ylabel('Counting (Log Scale)', color='b')
ax1.set_yscale('log')
ax1.legend(loc='upper left')

# 显示网格
ax1.grid(True, which="both", ls="--")

# 设置标题
plt.title('Binned Counting VS Rank')

# 显示图形
plt.show()



# import numpy as np
# import matplotlib.pyplot as plt
# import json
# import csv
# import os

# rank_dict = {}
# with open(os.path.join(os.path.dirname(__file__), r"../../../app/data/top-1m.csv"), 'r') as file:
#     csv_reader = csv.reader(file)
#     for row in csv_reader:
#         rank_dict[row[1]] = row[0]

# with open(r'H:/counting_out.json', 'r') as f:

#     json_data = json.load(f)
#     counting_data = {}

#     for domain, num in json_data.items():
#         rank = rank_dict[domain]
#         counting_data[rank] = num

# counting_data = dict(sorted(counting_data.items()))

# # x 轴：group index
# x = list(counting_data.keys())
# x = list(range(1, len(counting_data.keys()) + 1))
# y = list(counting_data.values())

# # 计算 CDF（累积分布函数）
# # cdf_data = np.cumsum(counting_data)
# # cdf_data = cdf_data / cdf_data[-1]  # 归一化到 0-1 范围

# # 创建图形
# fig, ax1 = plt.subplots(figsize=(10, 6))

# # 绘制柱状图，使用左侧 y 轴
# ax1.bar(x, y, width=0.8, color='b', label='Counting Growth')
# ax1.set_xlabel('Rank Index')
# ax1.set_ylabel('Counting (Log Scale)', color='b')
# ax1.set_yscale('log')
# ax1.legend(loc='upper left')

# # 创建第二个 y 轴，绘制 CDF 图
# # ax2 = ax1.twinx()
# # ax2.plot(x, cdf_data, marker='o', color='r', label='CDF', linestyle='--')
# # ax2.set_ylabel('CDF', color='r')
# # ax2.set_ylim(0, 1)  # CDF 的范围为 [0, 1]
# # ax2.legend(loc='upper right')

# # 显示网格
# ax1.grid(True, which="both", ls="--")

# # 设置标题
# plt.title('Counting VS Rank')

# # 显示图形
# plt.show()
