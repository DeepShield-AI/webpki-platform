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
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from datetime import datetime

# 示例数据
data = {
    "not_before_to_issuer": {
        "2022-12-06-00-00-00": [
            "Sectigo RSA Organization Validation Secure Server CA",
            "Sectigo RSA Organization Validation Secure Server CA"
        ],
        "2022-12-07-00-00-00": [
            "DigiCert Global Root CA",
            "Sectigo RSA Organization Validation Secure Server CA"
        ],
        "2022-12-08-00-00-00": [
            "GTS CA 1P5",
            "Sectigo RSA Organization Validation Secure Server CA",
            "Sectigo RSA Organization Validation Secure Server CA"
        ]
    }
}

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

plt.tight_layout()
plt.show()
