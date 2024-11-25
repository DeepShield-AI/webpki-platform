
import sys
sys.path.append(r"/root/pki-internet-platform")

from app.analyzer.cert_analyze_chain import CertScanChainAnalyzer
from app.parser.pem_parser import PEMParser

test_cert_path = r"test_certs/github.com_single.pem"

if __name__ == "__main__":
    with open(test_cert_path, "r") as f:
        pem_data = f.read().strip()

    analyzer = CertScanChainAnalyzer()
    pem_chain = analyzer.build_verified_chain(pem_data)
    parsed_chain = [PEMParser.parse_native_pretty(cert) for cert in pem_chain]
    print(len(parsed_chain))
    print(parsed_chain)
