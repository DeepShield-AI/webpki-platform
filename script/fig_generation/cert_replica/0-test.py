# import numpy as np
# import matplotlib.pyplot as plt

# # 示例数据
# data = np.random.randint(0, 10000, size=50000)

# # 设置 bin 的数量，例如 bin = 1000
# bin_size = 1000
# bins = np.arange(0, max(data) + bin_size, bin_size)

# # 生成直方图数据
# counts, bin_edges = np.histogram(data, bins=bins)

# # 绘制柱状图
# plt.bar(bin_edges[:-1], counts, width=bin_size, edgecolor='black', align='edge')
# plt.xlabel('Range')
# plt.ylabel('Count')
# plt.title('Binned Data Histogram')
# plt.show()
# import matplotlib.pyplot as plt
# import pandas as pd
# import seaborn as sns
# from datetime import datetime

# # 示例数据
# data = {
#     "not_before_to_issuer": {
#         "2022-12-06-00-00-00": [
#             "Sectigo RSA Organization Validation Secure Server CA",
#             "Sectigo RSA Organization Validation Secure Server CA"
#         ],
#         "2022-12-07-00-00-00": [
#             "DigiCert Global Root CA",
#             "Sectigo RSA Organization Validation Secure Server CA"
#         ],
#         "2022-12-08-00-00-00": [
#             "GTS CA 1P5",
#             "Sectigo RSA Organization Validation Secure Server CA",
#             "Sectigo RSA Organization Validation Secure Server CA"
#         ]
#     }
# }

# # 处理数据：统计每个时间点各个 CA 出现的次数，并转换时间格式
# rows = []
# for time_str, issuers in data["not_before_to_issuer"].items():
#     time = datetime.strptime(time_str, "%Y-%m-%d-%H-%M-%S")
#     for issuer in set(issuers):
#         rows.append({
#             "time": time,
#             "issuer": issuer,
#             "count": issuers.count(issuer)
#         })

# # 转换为 DataFrame
# df = pd.DataFrame(rows)

# # 绘制图表
# plt.figure(figsize=(12, 6))
# sns.lineplot(x="time", y="issuer", data=df, hue="issuer", marker="o", style="issuer", markers=True, legend=False)

# # 添加数量标注
# for index, row in df.iterrows():
#     plt.text(row['time'], row['issuer'], str(row['count']), color='black', ha="center")

# # 设置图表属性
# plt.xticks(rotation=45)
# plt.xlabel('Time')
# plt.ylabel('CA')
# plt.title('CA Distribution Over Time')

# plt.tight_layout()
# plt.show()


# import matplotlib.pyplot as plt
# import seaborn as sns
# import numpy as np

# # 示例数据
# data = {
#     "015bfdd9-2fd2-4a34-81e3-c15367c1bbce.rlets.com": {"rank": "758131", "valid_period": {"89": 2}},
#     "01net.com": {"rank": "411126", "valid_period": {"44": 1, "89": 1}},
#     # 其他数据...
# }

# # 将rank转为整数
# for key in data.keys():
#     data[key]['rank'] = int(data[key]['rank'])

# # 设置 bin 间隔
# bin_size = 10000
# max_rank = max(d['rank'] for d in data.values())
# bins = np.arange(0, max_rank + bin_size, bin_size)

# # 初始化 heatmap 数据结构
# heatmap_data = {}

# # 填充数据
# for entry in data.values():
#     rank_bin = bins[np.digitize(entry['rank'], bins) - 1]
#     if rank_bin not in heatmap_data:
#         heatmap_data[rank_bin] = {}
#     for period, count in entry['valid_period'].items():
#         if period not in heatmap_data[rank_bin]:
#             heatmap_data[rank_bin][period] = 0
#         heatmap_data[rank_bin][period] += count

# # 转换为百分比
# for rank_bin in heatmap_data:
#     total = sum(heatmap_data[rank_bin].values())
#     for period in heatmap_data[rank_bin]:
#         heatmap_data[rank_bin][period] /= total

# # 构造矩阵
# valid_periods = sorted({period for periods in heatmap_data.values() for period in periods})
# heatmap_matrix = np.zeros((len(valid_periods), len(bins)))

# for i, period in enumerate(valid_periods):
#     for j, rank_bin in enumerate(bins):
#         heatmap_matrix[i, j] = heatmap_data.get(rank_bin, {}).get(period, 0)

# # 绘制热力图
# plt.figure(figsize=(10, 8))
# sns.heatmap(heatmap_matrix, xticklabels=bins, yticklabels=valid_periods, cmap="YlGnBu")
# plt.xlabel("Rank Bin")
# plt.ylabel("Valid Period")
# plt.title("Heatmap of Valid Period Percentage by Rank")
# plt.show()

import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# 示例数据
data = {
    ("-1", "-2", "-3", "2*"): 3,
    ("-2", "-3", "2*"): 8,
    ("-1", "-3", "2*", "-2"): 6,
    # 添加更多的键值对
}

# 获取所有可能的序列元素并创建映射
all_elements = set([item for sequence in data.keys() for item in sequence])
element_mapping = {element: i for i, element in enumerate(sorted(all_elements))}

# 提取x, y, z坐标和计数
x = []
y = []
z = []
counts = []

for sequence, count in data.items():
    mapped_sequence = [element_mapping[element] for element in sequence]
    
    # 如果序列长度不足3，补齐为0（或你选择的填充值）
    while len(mapped_sequence) < 3:
        mapped_sequence.append(0)
    
    x.append(mapped_sequence[0])
    y.append(mapped_sequence[1])
    z.append(mapped_sequence[2])
    counts.append(count)

# 创建3D散点图
fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(111, projection='3d')

# 根据计数大小设置点的大小
sizes = [c * 20 for c in counts]

scatter = ax.scatter(x, y, z, s=sizes, c=sizes, cmap='viridis', alpha=0.6)

# 添加颜色条
fig.colorbar(scatter, ax=ax, label='Count')

# 设置坐标轴标签
ax.set_xlabel('X Axis')
ax.set_ylabel('Y Axis')
ax.set_zlabel('Z Axis')
ax.set_title('3D Scatter Plot of Sequence Group Sizes')

plt.show()
