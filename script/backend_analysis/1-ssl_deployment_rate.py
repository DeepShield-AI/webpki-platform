
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls

tot_num = 0
no_https = 0

tls_error = 0
weak_tls_version = 0
weak_tls_cipher = 0

cert_error = 0
hostname_mismatch = 0
expired_certs = 0
self_signed_certs = 0

for row in stream_by_id(engine_tls.raw_connection(), "web_security"):

    error_code_list = json.loads(row[1])
    tot_num += 1

    if 'no_https' in error_code_list:
        no_https += 1

    if 'no_weak_tls_cipher' in error_code_list or 'weak_tls_version' in error_code_list:
        tls_error += 1 
    if 'weak_tls_version' in error_code_list:
        weak_tls_version += 1
    if 'no_weak_tls_cipher' in error_code_list:
        weak_tls_cipher += 1

    if 'hostname_mismatch' in error_code_list or 'expired_certs' in error_code_list or 'self_signed_certs' in error_code_list:
        cert_error += 1
    if 'hostname_mismatch' in error_code_list:
        hostname_mismatch += 1
    if 'expired_certs' in error_code_list:
        expired_certs += 1
    if 'self_signed_certs' in error_code_list:
        self_signed_certs += 1

print(tot_num)
print(no_https)

print(tls_error)
print(weak_tls_version)
print(weak_tls_cipher)

print(cert_error)
print(hostname_mismatch)
print(expired_certs)
print(self_signed_certs)

# 56530751
# 39362981
# 0.6963109511847808

'''
4518306
1429724
0
0
0
1924796
1837138
379985
264802
'''