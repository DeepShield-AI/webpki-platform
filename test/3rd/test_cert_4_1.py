
import sys
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.celery.celery_db_pool import engine_cert
from backend.config.scan_config import InputScanConfig
from backend.parser.asn1_parser import ASN1Parser
from backend.scanner.celery_scan_task import _do_ssl_handshake
from backend.utils.cert import get_sha256_hex_from_bytes
from backend.utils.network import resolve_host_dns
from pprint import pprint

domain = sys.argv[1]
v4_records = resolve_host_dns(domain)[0]
ip = v4_records[0]

print(f"Test Domain: {domain}")
print(f"Resolved IP: {ip}")

ssl_result = _do_ssl_handshake(domain, ip, InputScanConfig(proxy_host=None, proxy_port=None))
peer_certs = ssl_result["peer_certs"]

print(ASN1Parser.der2pem(peer_certs[0]))

cert_conn = engine_cert.raw_connection()
cert_data = []

for i, cert_der_bytes in enumerate(peer_certs):
    cert_sha256 = get_sha256_hex_from_bytes(cert_der_bytes)
    cert_data.append((cert_sha256, cert_der_bytes))

if not cert_data:
    print("No certs retrieved on this domain, please use another one")
    exit(0)

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
