
import os, csv, sys, json
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.celery.celery_db_pool import engine_tls
from pprint import pprint

test_path = os.path.join(os.path.dirname(__file__), sys.argv[1])

label_num = 0
label_correct = 0

with open(test_path, 'r') as f:
    reader = csv.reader(f)
    
    for data in reader:
        domain, ip, label = data[0], data[1], data[2]
        label_num += 1

        tls_conn = engine_tls.raw_connection()
        with tls_conn.cursor() as cursor:
            query = """
                SELECT * FROM tlshandshake
                WHERE destination_host = %s AND destination_ip = %s
            """
            cursor.execute(query, (domain, ip))
            row = cursor.fetchone()

        analyze_result = _web_security_analyze(
            row[1],
            row[2],
            row[-4],
            row[-3],
            json.loads(row[-2])
        )
        pprint(analyze_result)

        if analyze_result["error_code"] and label == "bad":
            label_correct += 1
        elif not analyze_result["error_code"] and label == "good":
            label_correct += 1

print("Result:")
print(f"Total test domain num: {label_num}")
print(f"Correct predict num: {label_correct}")
print(f"Analyze accuracy: {label_correct / label_num}")
