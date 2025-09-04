
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
error = 0

expired = 0
validity_too_long = 0
weak_rsa = 0
weak_hash = 0
not_asn1 = 0
self_signed = 0
wrong_version = 0
wrong_key_usage = 0
no_revoke = 0
no_sct = 0

new_conn = engine_cert.raw_connection()
for row in stream_by_id(engine_cert.raw_connection(), "cert_trust"):
    trust = row[2]
    if int(trust) == 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_security
            WHERE id = %s
        """
        cursor.execute(query, (row[0],))
        row = cursor.fetchone()

    if row:
        error_code_list = json.loads(row[1])
        tot_num += 1

        if len(error_code_list) > 0:
            error += 1

        if 'expired' in error_code_list:
            expired += 1
        if 'validity_too_long' in error_code_list:
            validity_too_long += 1
        if 'weak_rsa' in error_code_list:
            weak_rsa += 1
        if 'weak_hash' in error_code_list:
            weak_hash += 1
        if 'not_asn1' in error_code_list:
            not_asn1 += 1
        if 'self_signed' in error_code_list:
            self_signed += 1
        if 'wrong_version' in error_code_list:
            wrong_version += 1
        if 'wrong_key_usage' in error_code_list:
            wrong_key_usage += 1
        if 'no_revoke' in error_code_list:
            no_revoke += 1
        if 'no_sct' in error_code_list:
            no_sct += 1

print(tot_num)
print(error)

print(expired)
print(validity_too_long)
print(weak_rsa)
print(weak_hash)
print(not_asn1)
print(self_signed)
print(wrong_version)
print(wrong_key_usage)
print(no_revoke)
print(no_sct)

'''
748206
601203
131487
245524
22101
13778
165
201666
25736
270439
447625
371483

'''