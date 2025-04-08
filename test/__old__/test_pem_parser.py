
import sys
sys.path.append(r"D:\global_ca_monitor")
from backend.parser.pem_parser import PEMParser
from backend.parser.cert_asn1_struct_fp import ASN1StructFP
from backend.utils.json import custom_serializer

import json
with open(r'test_certs/baidu.com_single.pem', 'r') as f:
# with open(r'test_certs/github.com_single.pem', 'r') as f:
    data = f.read()

    pem_parser = PEMParser()
    cert = pem_parser.parse_native_pretty(data)
    with open("out.json", 'w') as f:
        json.dump(cert, f, indent=4, default=custom_serializer)

    fp_constructor = ASN1StructFP()
    fp, fp_raw = fp_constructor.build_fp(pem_parser.parse_native(data))
    print(fp)
    print(fp_raw)

    # for ext in extensions:
    #     ext_id = ext['extn_id']
    #     if ext_id == 'signed_certificate_timestamp_list':
    #         sct_bytes = ext['extn_value']
    #         # print(sct_bytes.hex())
    #         # parse_sct(sct_bytes)
    #         # print(sct_bytes)
