
# INSERT INTO cert_subject_cn (id, cn)
# SELECT cs.id, jt.cn
# FROM cert_search cs,
#      JSON_TABLE(cs.subject_cn_list, '$[*]'
#        COLUMNS(cn VARCHAR(255) PATH '$')
#      ) AS jt
# WHERE jt.cn IS NOT NULL;

# SELECT cs.id, jt.cn
# FROM cert_search cs,
#      JSON_TABLE(cs.subject_cn_list, '$[*]'
#        COLUMNS(cn VARCHAR(255) PATH '$')
#      ) AS jt
# WHERE jt.cn IS NOT NULL
# LIMIT 5;

# INSERT INTO cert_subject_cn (id, cn)
# SELECT cs.id, jt.cn
# FROM cert_search cs,
#      JSON_TABLE(cs.subject_cn_list, '$[*]'
#        COLUMNS(cn VARCHAR(255) PATH '$')
#      ) AS jt
# WHERE jt.cn IS NOT NULL
# LIMIT 5;


import json
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_db_pool import engine_cert

BATCH_SIZE = 5000
start_id = 10452301
count = 0
batch = []

cert_conn = engine_cert.raw_connection()
with cert_conn.cursor() as cursor:
    for row in stream_by_id(engine_cert.raw_connection(), "cert_search", start_id=start_id):
        count += 1

        id = row[0]
        subject_cn_list = json.loads(row[3])

        for cn in subject_cn_list:
            if not cn: continue
            # assert(type(cn) == str)
            batch.append((id, json.dumps(cn)))

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(
                """
                INSERT INTO cert_subject_cn (id, cn) VALUES (%s, %s)
                """,
                batch
            )
            cert_conn.commit()
            print(f"✅ 插入 {count} 行")
            batch.clear()

    # 插入剩余
    if batch:
        cursor.executemany(
              """
              INSERT INTO cert_subject_cn (id, cn) VALUES (%s, %s)
              """,
            batch
        )
        cert_conn.commit()
        print(f"✅ 插入 {count} 行")
        batch.clear()

cert_conn.close()
print(f"🎉 插入完成，共计 {count} 行")
