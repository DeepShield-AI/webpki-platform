

import json
from collections import defaultdict

# 读取 JSON 文件
with open("/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph_revised", "r") as f:
    data = json.load(f)

# 统计 target 对应的 source 数量
target_count = defaultdict(int)

for link in data["links"]:
    target_count[link["target"]] += 1

# 打印统计结果
n = 0
for target, count in target_count.items():
    n += (count - 1)
    print(f"Target: {target}, Source Count: {count}")
print(n)
