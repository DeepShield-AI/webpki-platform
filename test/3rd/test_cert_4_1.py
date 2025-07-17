
import os
from backend.parser.pem_parser import ASN1Parser
from backend.utils.network import resolve_host_dns
from backend.config.scan_config import InputScanConfig
from backend.scanner.celery_scan_task import _do_ssl_handshake
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.utils.cert import get_sha256_hex_from_bytes
from pprint import pprint


domain = "www.baidu.cn"

v4_records = resolve_host_dns(domain)[0]
test_record = v4_records[0]

ssl_result = _do_ssl_handshake(domain, test_record, InputScanConfig())
values = list(ssl_result.values())

values[-2] = 

analyze_result = _web_security_analyze([0, domain, test_record, "", "", ""] + values, ".")
pprint(analyze_result)
