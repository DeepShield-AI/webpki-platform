import csv
import base64
from backend.analyzer.celery_cert_security_task import _cert_security_analyze
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert, engine_tls

good_sha = []
good_num = 80

bad_sha = []
bad_num = 20

out_file = open("certs.csv", "w")
csv_writer = csv.writer(out_file)
for row in stream_by_id(engine_cert.raw_connection(), "cert"):

    analyze_result = _cert_security_analyze(row, ".")
    if len(analyze_result.get("error_code", [])) > 0:
        label = "bad"
        if len(bad_sha) < bad_num:
            bad_sha.append(row[1])
            csv_writer.writerow([base64.b64encode(row[2]).decode('utf-8'), label])
    else:
        label = "good"
        if len(good_sha) < good_num:
            good_sha.append(row[1])
            csv_writer.writerow([base64.b64encode(row[2]).decode('utf-8'), label])

out_file.close()
