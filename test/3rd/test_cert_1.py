
import os, sys
from backend.parser.asn1_parser import ASN1Parser
from pprint import pprint

test_cert_path = os.path.join(os.path.dirname(__file__), sys.argv[1])
with open(test_cert_path, 'r') as f:
    data = f.read()

    pem_parser = ASN1Parser()
    cert = pem_parser.parse_pem_cert(data)
    pprint(cert)
