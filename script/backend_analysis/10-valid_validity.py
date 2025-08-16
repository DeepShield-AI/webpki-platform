
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
validity = []
new_conn = engine_cert.raw_connection()

for row in stream_by_id(engine_cert.raw_connection(), "cert_trust"):
    trust = row[2]
    if int(trust) != 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_search
            WHERE type = 0
            AND id = %s
        """
        cursor.execute(query, (row[0],))
        row = cursor.fetchone()

    if row:
        issuer = row[0]
        not_valid_before = row[-3]
        not_valid_after = row[-2]
        days = (not_valid_after - not_valid_before).days
        validity.append((not_valid_before.isoformat(), not_valid_after.isoformat()))

with open("10-out.json", "w") as f:
    json.dump(validity, f)
