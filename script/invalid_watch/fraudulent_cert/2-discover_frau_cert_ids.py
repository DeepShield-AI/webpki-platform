
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

trust_ca_names = []
new_conn = engine_cert.raw_connection()
with open("12-out.txt", "r", encoding="utf-8") as f:
    for line in f.readlines():
        print(line)
        trust_ca_names.append(line.strip())

with open("12-forged_ids.txt", "w") as f:

    for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):
        id = row[0]
        subject = row[4]
        issuer = row[5]
        type = row[-1]

        if issuer not in trust_ca_names: continue
        with new_conn.cursor() as cursor:
            query = """
                SELECT * from cert_trust
                WHERE id = %s
            """
            cursor.execute(query, (id,))
            row = cursor.fetchone()

        if row:
            trust = row[-1]
            if int(trust) != 0:
                # print(id)
                f.write(str(id))
                f.write('\n')
