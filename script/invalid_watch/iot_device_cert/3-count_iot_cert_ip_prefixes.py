
import csv
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls, engine_cert
from collections import defaultdict

# /8 网段统计
count_by_slash8 = defaultdict(int)

# /16 网段统计
count_by_slash16 = defaultdict(int)

with open("13-iot_ip.txt", "r") as input:
    for ip in input:
        ip = ip.strip()
        # 取 /8 网段（IP 第一个八位）
        first_octet = ip.split('.')[0]
        count_by_slash8[first_octet] += 1

        parts = ip.split('.')
        if len(parts) != 4:
            continue  # 跳过非法 IP

        # 取 /16 网段（IP 前两个八位）
        slash16 = f"{parts[0]}.{parts[1]}"
        count_by_slash16[slash16] += 1

# 打印 /8 统计结果
print("\n/8 网段统计：")
for slash8, count in sorted(count_by_slash8.items(), key=lambda x: int(x[0])):
    print(f"{slash8}.x.x.x\t{count}")

# 如果需要保存为 JSON
with open("13-slash8_count-device.json", "w", encoding="utf-8") as out:
    json.dump(count_by_slash8, out, ensure_ascii=False, indent=2)

# 打印 /16 统计结果
print("\n/16 网段统计：")
for slash16, count in sorted(count_by_slash16.items(), key=lambda x: (int(x[0].split('.')[0]), int(x[0].split('.')[1]))):
    print(f"{slash16}.x.x\t{count}")

# 保存为 JSON
with open("13-slash16_count-device.json", "w", encoding="utf-8") as out:
    json.dump(count_by_slash16, out, ensure_ascii=False, indent=2)


# 假设你有个 JSON 文件 slash16_data.json，格式是 {"159.87": 244, ...}
input_json_path = "13-slash16_count-device.json"

with open(input_json_path, "r", encoding="utf-8") as f:
    data = json.load(f)  # 读取 JSON dict

# 写拆分数字版 CSV
with open("13-slash16_heatmap.csv", "w", newline="", encoding="utf-8") as f_csv:
    writer = csv.writer(f_csv)
    writer.writerow(["FirstOctet", "SecondOctet", "Count"])
    for key, count in data.items():
        parts = key.split(".")
        if len(parts) == 2:
            try:
                first = int(parts[0])
                second = int(parts[1])
                writer.writerow([first, second, count])
            except ValueError:
                # 非数字忽略或处理
                continue

from collections import Counter
counter = Counter(count_by_slash16)
top10 = counter.most_common(100)

for name, count in top10:
    print(name, count)

'''
199.232 2712
140.248 1728
13.111 1697
128.245 1400
39.136 1072
34.132 813
34.171 802
34.134 802
34.170 795
34.121 783
34.173 779
34.136 777
34.67 777
34.172 777
34.122 776
34.133 772
34.123 771
34.71 770
35.238 768
34.91 768
34.72 764
34.30 758
38.15 757
161.71 753
34.70 750
34.29 750
35.223 750
34.42 749
34.27 749
34.28 748
'''
