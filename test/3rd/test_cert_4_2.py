
import os, csv, sys
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.config.scan_config import InputScanConfig
from backend.celery.celery_db_pool import engine_cert
from backend.scanner.celery_scan_task import _do_ssl_handshake
from backend.utils.cert import get_sha256_hex_from_bytes
from pprint import pprint

test_path = os.path.join(os.path.dirname(__file__), sys.argv[1])

label_num = 0
label_correct = 0

with open(test_path, 'r') as f:
    reader = csv.reader(f)
    
    for data in reader:
        domain, ip, label = data[0], data[1], data[2]
        label_num += 1

        ssl_result = _do_ssl_handshake(domain, ip, InputScanConfig(proxy_host=None, proxy_port=None))
        peer_certs = ssl_result["peer_certs"]

        cert_conn = engine_cert.raw_connection()
        cert_data = []

        for i, cert_der_bytes in enumerate(peer_certs):
            cert_sha256 = get_sha256_hex_from_bytes(cert_der_bytes)
            cert_data.append((cert_sha256, cert_der_bytes))

        if not cert_data:
            print("No certs retrieved on this domain, please use another one")

        with cert_conn.cursor() as cursor:
            cursor.executemany(
                "INSERT IGNORE INTO cert (sha256, cert_der) VALUES (%s, %s)",
                cert_data
            )
        cert_conn.commit()

        cert_sha256_data = [data[0] for data in cert_data]
        analyze_result = _web_security_analyze(
            domain,
            ip,
            ssl_result["tls_version"],
            ssl_result["tls_cipher"],
            cert_sha256_data
        )
        pprint(analyze_result)

        if analyze_result["error_code"] and label == "bad":
            label_correct += 1
        elif not analyze_result["error_code"] and label == "good":
            label_correct += 1

print("Result:")
print(f"Total test domain num: {label_num}")
print(f"Correct predict num: {label_correct}")
print(f"Analyze accuracy: {label_correct / label_num}")
