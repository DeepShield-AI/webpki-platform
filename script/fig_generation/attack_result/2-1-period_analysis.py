
from scipy.signal import correlate
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import json
import csv
import sys
sys.path.append(r"D:\global_ca_monitor")
from app.utils.json import custom_serializer

def check_entry_time(timestamp):
    timestamp_seconds = timestamp / 1000
    date_time = datetime.fromtimestamp(timestamp_seconds)
    formatted_date = date_time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"Timestamp: {formatted_date}")

# 计算差值
def compute_differences(seq):
    return np.diff(seq)

# 计算自相关函数
def autocorrelation(x):
    n = len(x)
    variance = np.var(x)
    x = x - np.mean(x)
    result = correlate(x, x, mode='full')
    result = result / (variance * n)
    result = result[n - 1:]
    return result

# 计算傅里叶变换
def fourier_transform(x):
    return np.fft.fft(x)

def compute_chunk_info(days_list):
    chunks = []
    days_between_chunks = []
    current_chunk_size = 1
    for value in days_list:
        if value == 0:
            current_chunk_size += 1
        else:
            chunks.append(current_chunk_size)
            days_between_chunks.append(value)
            current_chunk_size = 1

    chunks.append(current_chunk_size)
    return chunks, days_between_chunks

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'2.txt', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

    count_dict = {}
    for domain, timestamps in json_data.items():
        if len(timestamps) > 0:

            # 计算差值序列
            microseconds_per_day = 86400 * 10**3
            microseconds_per_hour = 3600 * 10**3
            microseconds_per_min = 60 * 10**3

            microseconds_list = compute_differences(sorted(timestamps))
            days_list = [int(x / microseconds_per_day) for x in microseconds_list]
            hours_list = [int(x / microseconds_per_hour) for x in microseconds_list]
            # print(days_list)

            chunks, days_between_chunks = compute_chunk_info(days_list)
            count_dict[domain] = {
                "issue_cert_in_single_chunk" : chunks,
                "time_period_between_chunks" : days_between_chunks
            }

with open("2-1.txt", "w", encoding='utf-8') as file:
    json.dump(count_dict, file, indent=4, default=custom_serializer)
