
import numpy as np
import matplotlib.pyplot as plt
import json

with open(r'../../../data/cert_replica/20K_out.txt', 'r') as f:

    json_data = json.load(f)

    counting_data = []

    for entry in json_data:
        counting_data.append(entry["Count"])

counting_data.sort()

# x 轴：group index
x = list(range(1, len(counting_data) + 1))

# 计算 CDF（累积分布函数）
cdf_data = np.cumsum(counting_data)
cdf_data = cdf_data / cdf_data[-1]  # 归一化到 0-1 范围

# 创建图形
fig, ax1 = plt.subplots(figsize=(10, 6))

# 绘制柱状图，使用左侧 y 轴
ax1.bar(x, counting_data, width=0.8, color='b', label='Counting Growth')
ax1.set_xlabel('Group Index')
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

# 设置标题
plt.title('Counting Growth and CDF per Group')

# 显示图形
plt.show()
