
import json
import csv

# 假设你有个 JSON 文件 slash16_data.json，格式是 {"159.87": 244, ...}
input_json_path = "0-slash16_count.json"

with open(input_json_path, "r", encoding="utf-8") as f:
    data = json.load(f)  # 读取 JSON dict

# 写拆分数字版 CSV
with open("0-slash16_heatmap.csv", "w", newline="", encoding="utf-8") as f_csv:
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
