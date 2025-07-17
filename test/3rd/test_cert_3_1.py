
import os, sys
from backend.parser.asn1_parser import ASN1Parser
from backend.analyzer.celery_cert_security_task import _cert_security_analyze
from backend.utils.cert import get_sha256_hex_from_bytes
from pprint import pprint

test_cert_path = os.path.join(os.path.dirname(__file__), sys.argv[1])
with open(test_cert_path, 'r') as f:
    pem_data = f.read()

    der_bytes = ASN1Parser.pem2der(pem_data)
    analyze_result = _cert_security_analyze(get_sha256_hex_from_bytes(der_bytes), der_bytes)
    pprint(analyze_result)
