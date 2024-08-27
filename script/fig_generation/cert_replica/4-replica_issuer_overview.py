
ca_orgs = [
    "Cloudflare",
    "DigiCert",
    "Entrust",
    "Microsoft",
    "Amazon",
    "Encryption Everywhere",
    "GeoTrust"
]


import numpy as np
import matplotlib.pyplot as plt
import json
import csv
import os
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from datetime import datetime

# 读取排名数据
rank_dict = {}
with open(os.path.join(os.path.dirname(__file__), r"../../../app/data/top-1m.csv"), 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/counting_out.json', 'r') as f:
    json_data = json.load(f)
    issuer_counting_data = {}

    more_than_one_issuer = 0

    for domain, data in json_data.items():
        rank = rank_dict[domain]

        if len(data['issuer_cn'].keys()) > 1:
            more_than_one_issuer += 1

        for type, num in data['issuer_cn'].items():
            if type not in issuer_counting_data:
                issuer_counting_data[type] = 0

            issuer_counting_data[type] += num

print(issuer_counting_data)
print(more_than_one_issuer)


# 读取 JSON 数据
with open(r'H:/counting_out.json', 'r') as f:
    json_data = json.load(f)

    for domain, data in json_data.items():
        rank = rank_dict[domain]

        if len(data['issuer_cn'].keys()) > 1:
            # 处理数据：统计每个时间点各个 CA 出现的次数，并转换时间格式
            rows = []
            for time_str, issuers in data["not_before_to_issuer"].items():
                time = datetime.strptime(time_str, "%Y-%m-%d-%H-%M-%S")
                for issuer in set(issuers):
                    rows.append({
                        "time": time,
                        "issuer": issuer,
                        "count": issuers.count(issuer)
                    })

            # 转换为 DataFrame
            df = pd.DataFrame(rows)

            # 绘制图表
            plt.figure(figsize=(12, 6))
            sns.lineplot(x="time", y="issuer", data=df, hue="issuer", marker="o", style="issuer", markers=True, legend=False)

            # 添加数量标注
            for index, row in df.iterrows():
                plt.text(row['time'], row['issuer'], str(row['count']), color='black', ha="center")

            # 设置图表属性
            plt.xticks(rotation=45)
            plt.xlabel('Time')
            plt.ylabel('CA')
            plt.title('CA Distribution Over Time')
            plt.legend()

            plt.tight_layout()
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
