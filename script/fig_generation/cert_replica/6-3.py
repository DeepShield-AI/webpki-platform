
import numpy as np
import matplotlib.pyplot as plt
import json

with open('6-3-1.txt', 'r') as f:
    domain_data = json.load(f)

# 初始化密钥的使用次数字典
key_reuse_sans = []

# 遍历所有域名和其公钥
for key, data in domain_data.items():
    key_reuse_sans.append(len(data))

# 计算并绘制CDF
sorted_average_diffs_days = np.sort(key_reuse_sans)
cdf = np.arange(0, len(sorted_average_diffs_days)) / len(sorted_average_diffs_days)

plt.plot(sorted_average_diffs_days, cdf, marker='o')
plt.title("CDF")
plt.xlabel("Reuse across SANs")
plt.ylabel("CDF")
plt.grid(True)
plt.savefig('6-3.png', dpi=300, bbox_inches='tight')
plt.show()
