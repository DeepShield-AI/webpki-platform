
data = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 10]

chunks = []
days_between_chunks = []

current_chunk_size = 1
for value in data:

    if value == 0:
        current_chunk_size += 1
    else:
        chunks.append(current_chunk_size)
        days_between_chunks.append(value)
        current_chunk_size = 1

chunks.append(current_chunk_size)

print("Chunks (连续非零块的大小):", chunks)
print("Days between chunks (相邻chunk之间的天数):", days_between_chunks)

import json

# 读取 JSON 数据
count = 0
with open(r'1.txt', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

    count_dict = {}
    for domain, data in json_data.items():
        if len(data) > 0:
            count += 1
print(count)
