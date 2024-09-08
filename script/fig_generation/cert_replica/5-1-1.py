

from datetime import datetime
import json
import matplotlib.pyplot as plt
import numpy as np

with open('5-1-1.txt', 'r') as f:
    data = json.load(f)

# 存储所有域名的协方差值
covariances = []

# 遍历每个域名的数据
for domain, domain_data in data.items():
    # 将日期按照时间顺序排序
    sorted_dates = sorted(domain_data.keys(), key=lambda x: datetime.strptime(x, "%Y-%m-%d"))
    sorted_values = [domain_data[date] for date in sorted_dates]

    # 将日期转换为数值格式 (这里将日期转换为天数)
    sorted_dates_numeric = [i for i in range(len(sorted_dates))]     # use index
    # sorted_dates_numeric = [(datetime.strptime(date, "%Y-%m-%d") - datetime.strptime(sorted_dates[0], "%Y-%m-%d")).month for date in sorted_dates]

    # 计算协方差
    covariance = np.cov(sorted_dates_numeric, sorted_values)[0][1]
    covariances.append(covariance)
    # print(f"Domain: {domain}, Covariance: {covariance}")

# 计算并绘制CDF
sorted_covariances = np.sort(covariances)
cdf = np.arange(1, len(sorted_covariances) + 1) / len(sorted_covariances)

plt.plot(sorted_covariances, cdf, marker='o')
plt.title("CDF of Covariances")
plt.xlabel("Covariance")
# plt.xscale('log')
plt.ylabel("CDF")
plt.grid(True)
plt.show()

