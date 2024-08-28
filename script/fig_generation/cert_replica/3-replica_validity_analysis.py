
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json

with open(r'../../../data/cert_replica/20K_out.txt', 'r') as f:

    json_data = json.load(f)
    overlap_day_data = {}

    i = 0
    for entry in json_data:
        overlap_day_data[i] = (entry["Overlap_Percent"])
        i += 1

print(len(overlap_day_data.keys()))

# 定义分组函数，将 key 转换为指定的区间范围
def group_key(key, group_size=1):
    key = int(float(key))  # 确保 key 是整数
    return (key // group_size) * group_size

# 初始化聚合后的数据结构
grouped_data = defaultdict(lambda: defaultdict(int))

# 对每个 group 的数据进行分组和聚合
for group, data in overlap_day_data.items():
    for key, value in data.items():
        grouped_key = group_key(key)
        grouped_data[group][grouped_key] += value

# 所有可能的分组区间
all_groups = sorted(set(key for group in grouped_data.values() for key in group.keys()))
print(all_groups)

# 构建一个二维数组，行是区间范围，列是group，值是每个group中对应区间的value
data_matrix = []

# 计算每个 group 的总数，用于计算占比
totals = {group: sum(grouped_data[group].values()) for group in grouped_data}

for grouped_key in all_groups:
    row = []
    for group, group_data in grouped_data.items():
        # 如果当前分组 key 存在于该 group 中，使用该值，否则使用 0
        value = group_data.get(grouped_key, 0)
        # 计算占比
        row.append(value / totals[group])
    data_matrix.append(row)

# 转置矩阵，使得列是 group，行是 key（天数）
data_matrix = np.array(data_matrix)

# 创建热力图
plt.figure(figsize=(10, 6))
ax = sns.heatmap(data_matrix, cmap="YlGnBu", xticklabels=list(grouped_data.keys()), yticklabels=all_groups, annot=False)

# # 设置横坐标标签，仅显示特定的 group 标签（如隔一个显示一个）
ax.set_xticks([0, 50, 100, 150, 200])  # 设置你想显示的 tick 位置
ax.set_xticklabels(['1', '51', '101', '151', '201'])  # 对应位置显示的标签

# 反转 y 轴方向，使其从下到上变为从小到大
ax.invert_yaxis()

# 设置标题和标签
plt.title('Heatmap of Overlap Day Distribution per Group (Grouped by Interval)')
plt.xlabel('Group Index')
plt.ylabel('Overlap Day Range (Key)')

# 显示图形
plt.show()


# with open(r'../../../data/cert_replica/20K_out.txt', 'r') as f:

#     json_data = json.load(f)
#     overlap_day_data = {}

#     i = 0
#     for entry in json_data:
#         overlap_day_data[i] = (entry["Overlap_Day"])
#         i += 1

# print(len(overlap_day_data.keys()))

# # 所有可能的 key（天数）
# all_keys = sorted(set(key for group in overlap_day_data.values() for key in group.keys()))

# # 构建一个二维数组，行是key（天数），列是group，值是每个group中对应key的value
# data_matrix = []

# # 计算每个 group 的总数，用于计算占比
# totals = {group: sum(overlap_day_data[group].values()) for group in overlap_day_data}

# for key in all_keys:
#     row = []
#     for group, group_data in overlap_day_data.items():
#         # 如果当前 key 存在于该 group 中，使用该值，否则使用 0
#         value = group_data.get(key, 0)
#         # 计算占比
#         row.append(value / totals[group])
#     data_matrix.append(row)

# # 转置矩阵，使得列是 group，行是 key（天数）
# data_matrix = np.array(data_matrix)

# # 创建热力图
# plt.figure(figsize=(10, 6))
# ax = sns.heatmap(data_matrix, cmap="YlGnBu", xticklabels=list(overlap_day_data.keys()), yticklabels=all_keys, annot=False)

# # 设置横坐标标签，仅显示特定的 group 标签（如隔一个显示一个）
# ax.set_xticks([0, 50, 100, 150, 200])  # 设置你想显示的 tick 位置
# ax.set_xticklabels(['1', '51', '101', '151', '201'])  # 对应位置显示的标签

# # 反转 y 轴方向，使其从下到上变为从小到大
# # ax.invert_yaxis()

# # 设置标题和标签
# plt.title('Heatmap of Overlap Day Distribution per Group')
# plt.xlabel('Group Index')
# plt.ylabel('Overlap Day (Key)')

# # 显示图形
# plt.show()
