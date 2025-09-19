
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

# discover all trust ca names
trust_ca_names = set()

new_conn = engine_cert.raw_connection()
for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):
    id = row[0]
    subject = row[4]
    type = row[-1]
    if int(type) == 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_trust
            WHERE id = %s
        """
        cursor.execute(query, (id,))
        row = cursor.fetchone()

    if row:
        trust = row[-1]
        if int(trust) == 0:
            trust_ca_names.add(subject)

with open("12-out.txt", "w") as f:
    for name in trust_ca_names:
        f.write(name + '\n')
