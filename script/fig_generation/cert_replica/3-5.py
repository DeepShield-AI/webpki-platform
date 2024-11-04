
import numpy as np
import matplotlib.pyplot as plt
import json

with open('3-5.txt', 'r') as f:
    data = json.load(f)

# 存储所有域名的平均时间差（以天为单位）
average_diffs_days = []

# 遍历每个域名的数据
for domain, timestamps in data.items():
    # 计算时间戳之间的差值（以毫秒为单位）
    diffs = np.diff(timestamps)
    
    # 将时间差转换为天（1天 = 86400000毫秒）
    diffs_days = diffs / 86400000
    
    # 计算平均时间差
    average_diff_days = np.mean(diffs_days)
    average_diffs_days.append(average_diff_days)
    # print(f"Domain: {domain}, Average Difference in Days: {average_diff_days}")

# 计算并绘制CDF
sorted_average_diffs_days = np.sort(average_diffs_days)
cdf = np.arange(1, len(sorted_average_diffs_days) + 1) / len(sorted_average_diffs_days)

plt.plot(sorted_average_diffs_days, cdf, marker='o')
plt.title("CDF of Average Time Differences (in Days)")
plt.xlabel("Average Time Difference (Days)")
plt.ylabel("CDF")
plt.grid(True)
plt.savefig('3-5.png', dpi=300, bbox_inches='tight')
plt.show()
