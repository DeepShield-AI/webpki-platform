
import json
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_db_pool import engine_cert, engine_tls

BATCH_SIZE = 5000
start_id = 56530000
count = 0
batch = []

tls_conn = engine_tls.raw_connection()
with tls_conn.cursor() as cursor:
    for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake_old", start_id=start_id):
        count += 1

        sha_list = json.loads(row[8])
        if len(sha_list) == 0:
            leaf_sha = None
            chain_sha = []
        elif len(sha_list) == 1:
            leaf_sha = sha_list[0]
            chain_sha = []
        else:
            leaf_sha = sha_list[0]
            chain_sha = sha_list[1:]

        chain_sha = json.dumps(chain_sha)
        batch.append((
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            leaf_sha,
            chain_sha,
            row[9]
        ))

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(
                """
                INSERT IGNORE INTO tlshandshake (
                    id, destination_host, destination_ip, scan_time, jarm, jarm_hash,
                    tls_version, tls_cipher, leaf_sha256, chain_sha256, error
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                batch
            )
            tls_conn.commit()
            print(f"✅ 插入 {count} 行")
            batch.clear()

    # 插入剩余
    if batch:
        cursor.executemany(
            """
            INSERT IGNORE INTO tlshandshake (
                id, destination_host, destination_ip, scan_time, jarm, jarm_hash,
                tls_version, tls_cipher, leaf_sha256, chain_sha256, error
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            batch
        )
        tls_conn.commit()
        print(f"✅ 插入 {count} 行")
        batch.clear()

tls_conn.close()
print(f"🎉 插入完成，共计 {count} 行")
