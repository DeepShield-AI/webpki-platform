
import csv
import json
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls

good_domain = []
good_num = 80

bad_domain = []
bad_num = 20

out_file = open("domain.csv", "w")
csv_writer = csv.writer(out_file)
for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake"):
    if row[1] is None: continue

    if len(good_domain) >= good_num and len(bad_domain) >= bad_num:
        break

    analyze_result = _web_security_analyze(
        row[1],
        row[2],
        row[-4],
        row[-3],
        json.loads(row[-2])
    )
    if len(analyze_result.get("error_code", [])) > 0:
        if "no_https" in analyze_result.get("error_code", []): continue
        label = "bad"
        if len(bad_domain) < bad_num:
            if row[1] in bad_domain: continue
            bad_domain.append(row[1])
            csv_writer.writerow([row[1], row[2], label])
    else:
        label = "good"
        if len(good_domain) < good_num:
            if row[1] in good_domain: continue
            good_domain.append(row[1])
            csv_writer.writerow([row[1], row[2], label])

out_file.close()
