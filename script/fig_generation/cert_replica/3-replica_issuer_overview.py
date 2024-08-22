
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import numpy as np
import json

ca_orgs = [
    "Cloudflare",
    "DigiCert",
    "Entrust",
    "Microsoft",
    "Amazon",
    "Encryption Everywhere",
    "GeoTrust"
]

with open(r'../../../data/cert_replica/20K_out.txt', 'r') as f:

    json_data = json.load(f)
    group_data = {}
    cn_data = set()
    cn_number_data = []
    org_number_data = []

    ca_counting_data = {}

    i = 0
    for entry in json_data:

        # group_data[i] = entry["Issuer_cn"]
        # cn_number_data.append(len(entry["Issuer_cn"].keys()))
        # for ca, num in entry["Issuer_cn"].items():
        #     cn_data.add(ca)

        filtered =  {}
        for ca, num in entry["Issuer_cn"].items():
            for org in ca_orgs:
                if org in ca:
                    if org not in filtered:
                        filtered[org] = 0
                    filtered[org] += num

                    if org not in ca_counting_data:
                        ca_counting_data[org] = 0
                    ca_counting_data[org] += num

        group_data[i] = filtered
        org_number_data.append(len(filtered.keys()))
        i += 1

print(len(group_data.keys()))

org_number_data.sort()
print(ca_counting_data)

# x 轴：group index
x = list(range(1, len(org_number_data) + 1))

# 计算 CDF（累积分布函数）
cdf_data = np.cumsum(org_number_data)
cdf_data = cdf_data / cdf_data[-1]  # 归一化到 0-1 范围

# 创建图形
fig, ax1 = plt.subplots(figsize=(10, 6))

# 绘制柱状图，使用左侧 y 轴
ax1.bar(x, org_number_data, width=0.8, color='b', label='Counting Growth')
ax1.set_xlabel('Group Index')
ax1.set_ylabel('Counting (Log Scale)', color='b')
# ax1.set_yscale('log')
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



# # 计算总值和百分比
# percentages = {}
# for group, data in group_data.items():
#     total_value = sum(data.values())
#     percentages[group] = {key: (value / total_value) * 100 for key, value in data.items()}

# # 设置柱状图的宽度和位置
# bar_width = 0.5
# index = np.arange(len(group_data))

# # 绘制堆叠柱状图
# fig, ax = plt.subplots(figsize=(10, 6))

# # 生成 20 种颜色
# colors = cm.tab20(np.linspace(0, 1, 20))

# # 堆叠的起始位置
# bottoms = np.zeros(len(group_data))

# for i, key in enumerate(cn_data):
#     # 获取每个组的百分比数据
#     bars = [percentages[group].get(key, 0) for group in group_data]
    
#     # 绘制堆叠部分
#     ax.bar(index, bars, bar_width, bottom=bottoms, label=key, color=colors[i])
    
#     # 更新下一个堆叠的起始位置
#     bottoms += np.array(bars)

# # 设置x轴标签
# ax.set_xlabel('Group Index')
# ax.set_ylabel('Percentage (%)')
# ax.set_title('Stacked Percentage Distribution of Issuer_cn Across Groups')
# ax.set_xticks(index)
# ax.set_xticklabels(group_data.keys())
# ax.legend(title='Issuer_cn')

# plt.show()
