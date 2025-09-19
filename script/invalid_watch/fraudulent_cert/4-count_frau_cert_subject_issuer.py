
import csv
import json
import tldextract
from collections import Counter
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls

subject_cn_counter = Counter()
issuer_cn_counter = Counter()

leaf_sha256_list = []
with open("12-forged_details.csv", newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    for row in reader:
        try:
            record_id, leaf_sha256, subject_json, issuer_json, extra = row

            # 解析 JSON（注意里面有双双引号，需要替换）
            subject = json.loads(subject_json.replace('""', '"'))
            issuer = json.loads(issuer_json.replace('""', '"'))
            
            # 统计 common_name
            if "common_name" in subject:
                cn = subject["common_name"].lstrip("*.")
                ext = tldextract.extract(cn)
                sld = ext.domain + "." + ext.suffix if ext.suffix else ext.domain
                subject_cn_counter[sld] += 1
            if "common_name" in issuer:
                issuer_cn_counter[issuer["common_name"]] += 1
            
            leaf_sha256_list.append(leaf_sha256)

        except Exception as e:
            print(f"Error parsing row {row}: {e}")

print("\n=== Subject CN 全部统计（按出现次数排序） ===")
for cn, count in sorted(subject_cn_counter.items(), key=lambda x: x[1], reverse=True):
    print(cn, count)

print("\n=== Issuer CN 全部统计（按出现次数排序） ===")
for cn, count in sorted(issuer_cn_counter.items(), key=lambda x: x[1], reverse=True):
    print(cn, count)
