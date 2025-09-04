
import sys
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

# 读取 fp_out.json 文件
with open("8-fp_out.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# 提取需要检查的 fingerprint（SHA256 形式）
need_to_check_set = set()
need_to_check = defaultdict(list)

for k, v in data.items():
    print(k, len(v.keys()))
    if isinstance(v, dict) and len(v.keys()) > 10:
        # print(k)
        for sub_k, sub_v in v.items():
            if sub_v == 1:
                need_to_check[k].append(sub_k)
                need_to_check_set.add(sub_k)

# 根据数据库中的指纹匹配出需要检查的 ID
id_need_to_check = []

for row in stream_by_id(engine_cert.raw_connection(), "cert_fp"):
    cert_id = row[0]
    fp = row[1]
    fp_sha256 = row[2]

    if fp_sha256 in need_to_check_set:
        id_need_to_check.append(cert_id)

# 保存到文件
output_path = "8-id_need_to_check.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(id_need_to_check, f, indent=2)

print(f"Saved {len(id_need_to_check)} IDs to {output_path}")
