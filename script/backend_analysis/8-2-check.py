
import json
from datetime import datetime, timezone
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

single_key = 0
self_signed = 0
expired = 0

# 保存到文件
input_path = "8-id_need_to_check.json"
with open(input_path, "r", encoding="utf-8") as f:
    data = json.load(f)

new_conn = engine_cert.raw_connection()
for id in data:
    # print(id)
    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_search
            WHERE id = %s
        """

        cursor.execute(query, (id,))
        row = cursor.fetchone()

        if row:
            not_after = row[-2]
            now = datetime.now()

            if now > not_after:
                expired += 1

            issuer = json.loads(row[5])
            subject = json.loads(row[4])

            if issuer == subject and row[-1] != 2:
                # print(id)
                self_signed += 1

            # ski = row[-4]
            # query = """
            #     SELECT COUNT(*) from cert_search
            #     WHERE ski = %s
            # """

            # cursor.execute(query, (ski,))
            # row = cursor.fetchone()

            # if row[0] == 0:
            #     single_key += 1

print(expired)
print(self_signed)
print(single_key)

# 1398
# 6
# 0
'''
474618
1125015
1398182
2325670
3458467
4323791
'''