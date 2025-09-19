
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
ca_issuer_rate = defaultdict(int)
new_conn = engine_cert.raw_connection()

with open("13-id_seed.txt", "r") as input:
    for id in input:
        with new_conn.cursor() as cursor:
            query = """
                SELECT * from cert_search
                WHERE id = %s
            """
            cursor.execute(query, (id,))
            row = cursor.fetchone()

        if row:
            subject = row[4]
            if subject:
                subject = json.loads(subject)
                if isinstance(subject, dict):
                    ca_issuer_rate[str(subject)] += 1
                    tot_num += 1

for k, v in ca_issuer_rate.items():
    ca_issuer_rate[k] = v / tot_num

with open("13-subject.json", "w") as f:
    json.dump(ca_issuer_rate, f, indent=2)

with open("13-subject.json", "r") as f:
    my_dict = json.load(f)

top_100_keys = [k for k, v in sorted(my_dict.items(), key=lambda item: item[1], reverse=True)[:100]]

for key in top_100_keys:
    print(key, my_dict[key])


# with open("13-subject.json", "r") as f:
#     my_dict = json.load(f)

# # 假设 my_dict 是 {name: count} 这种形式
# counter = Counter(my_dict)

# # 取前 10
# top10 = counter.most_common(30)

# for name, count in top10:
#     print(name, count)

# exit(0)
