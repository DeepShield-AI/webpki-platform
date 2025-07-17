
import os
from backend.parser.pem_parser import ASN1Parser
from pprint import pprint

test_cert_path = os.path.join(os.path.dirname(__file__), "supplement/cert/github.com_single.pem")
with open(test_cert_path, 'r') as f:
    data = f.read()

    pem_parser = ASN1Parser()
    cert = pem_parser.parse_native_pretty_pem(data)
    pprint(cert)
