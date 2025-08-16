
import csv
import json

with open("10-out.json", mode="r", newline="") as f:
    data = json.load(f)

with open("10-out.csv", mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Time", "Value"])  # 写表头
    for row in data:
        # time_str = row[0].replace("T", " ")  # 替换T为空格
        # time_str1 = row[1].replace("T", " ")  # 替换T为空格
        time_str = row[0][:10]
        time_str1 = row[1][:10]
        writer.writerow([time_str, time_str1])

print("CSV 文件生成完毕：output.csv")
