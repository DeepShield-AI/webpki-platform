
import os, sys
from backend.parser.asn1_parser import ASN1Parser
from backend.analyzer.celery_cert_fp_task import ASN1StructFP
from pprint import pprint

test_cert_path = os.path.join(os.path.dirname(__file__), sys.argv[1])
with open(test_cert_path, 'r') as f:
    pem_data = f.read()

    der_bytes = ASN1Parser.pem2der(pem_data)
    asn1_fp = ASN1StructFP().build_fp(der_bytes)
    print(asn1_fp)
    