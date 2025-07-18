
import os, sys
from backend.utils.network import resolve_host_dns
from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import _do_ssl_handshake
from pprint import pprint

test_domain_path = os.path.join(os.path.dirname(__file__), sys.argv[1])
with open(test_domain_path) as input:
    for row in input:
        domain = row.strip()
        pprint(f"Domain: {domain}")
        v4_records, v6_records = resolve_host_dns(domain)
        for ip in v4_records + v6_records:
            pprint(f"IP: {ip}")
            ssl_result = _do_ssl_handshake(domain, ip, InputScanConfig(proxy_host=None, proxy_port=None))
            pprint(ssl_result)
