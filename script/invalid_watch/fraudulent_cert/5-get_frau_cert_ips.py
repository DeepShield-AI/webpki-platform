
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
            leaf_sha256_list.append(leaf_sha256)

        except Exception as e:
            print(f"Error parsing row {row}: {e}")

out = open("12-ip.txt", "w")

for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake"):
    ip = row[2]
    leaf_sha256 = row[-3]
    if leaf_sha256 in leaf_sha256_list:
        out.write(ip)
        out.write('\n')
