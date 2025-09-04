
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_db_pool import engine_ca
from backend.utils.cert import get_sha256_hex_from_str

BATCH_SIZE = 5000
start_id = 0
count = 0
batch = []

ca_conn = engine_ca.raw_connection()
with ca_conn.cursor() as cursor:
    for row in stream_by_id(engine_ca.raw_connection(), "ca_backup", start_id=start_id):
        count += 1

        subject = row[2]
        subject_sha256 = get_sha256_hex_from_str(subject)

        batch.append((
            row[0],
            row[1],
            row[2],
            subject_sha256,
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            row[8]
        ))

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(
                """
                INSERT IGNORE INTO ca (
                    id, sha256, subject, subject_sha256, spki, ski, certs, issued_certs, parent, child
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                batch
            )
            ca_conn.commit()
            print(f"✅ 插入 {count} 行")
            batch.clear()

    # 插入剩余
    if batch:
        cursor.executemany(
            """
            INSERT IGNORE INTO ca (
                id, sha256, subject, subject_sha256, spki, ski, certs, issued_certs, parent, child
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            batch
        )
        ca_conn.commit()
        print(f"✅ 插入 {count} 行")
        batch.clear()

ca_conn.close()
print(f"🎉 插入完成，共计 {count} 行")
