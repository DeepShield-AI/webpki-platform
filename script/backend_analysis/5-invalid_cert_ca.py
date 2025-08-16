
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
ca_issuer_rate = defaultdict(int)
new_conn = engine_cert.raw_connection()

for row in stream_by_id(engine_cert.raw_connection(), "cert_trust"):
    trust = row[2]
    if int(trust) == 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT issuer from cert_search
            WHERE id = %s
        """
        cursor.execute(query, (row[0],))
        row = cursor.fetchone()

    if row:
        issuer = row[0]
        if issuer:
            issuer = json.loads(issuer)
            if isinstance(issuer, dict):
                cn = issuer.get("common_name")
                ca_issuer_rate[str(cn)] += 1
                tot_num += 1

for k, v in ca_issuer_rate.items():
    ca_issuer_rate[k] = v / tot_num

with open("5-ca_out.json", "w") as f:
    json.dump(ca_issuer_rate, f, indent=2)

with open("5-ca_out.json", "r") as f:
    my_dict = json.load(f)

top_100_keys = [k for k, v in sorted(my_dict.items(), key=lambda item: item[1], reverse=True)[:100]]

for key in top_100_keys:
    print(key, my_dict[key])

