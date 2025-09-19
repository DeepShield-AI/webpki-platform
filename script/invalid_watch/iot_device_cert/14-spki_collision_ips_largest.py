
import json
from backend.celery.celery_db_pool import engine_cert, engine_tls

with open("13-spki_collision.json", "r") as f:
    my_dict = json.load(f)

ip_list = []
cert_conn = engine_cert.raw_connection()
tls_conn = engine_tls.raw_connection()

for sha, id_list in my_dict.items():
    if len(id_list) > 450:
        print(len(id_list), id_list[0])

        for cert_id in id_list:
                    
            with cert_conn.cursor() as cursor:
                query = """
                    SELECT * from cert
                    WHERE id = %s
                """
                cursor.execute(query, (cert_id,))
                row = cursor.fetchone()

            sha256 = row[1]
            with tls_conn.cursor() as cursor:
                query = """
                    SELECT destination_ip from tlshandshake
                    WHERE leaf_sha256 = %s
                """
                cursor.execute(query, (sha256,))
                rows = cursor.fetchall()

            if rows:
                ip_list += rows
                print(len(rows))

print(ip_list)
print(len(ip_list))
