
import sys
sys.path.append(r"D:\global_ca_monitor")
from app.parser.pem_parser import PEMParser
from app.utils.json import custom_serializer

import json
with open(r'test_certs/github.com_single.pem', 'r') as f:
    data = f.read()

    pem_parser = PEMParser()
    cert = pem_parser.parse_pem_cert(data)
    print(cert.pub_key)

    cert = pem_parser.parse_native(data)
    with open("out.json", 'w') as f:
        json.dump(cert, f, indent=4, default=custom_serializer)

    # json_str = json.dumps(cert, default=datetime_serializer)
    # extensions = cert['tbs_certificate']['extensions']

    # for ext in extensions:
    #     ext_id = ext['extn_id']
    #     if ext_id == 'signed_certificate_timestamp_list':
    #         sct_bytes = ext['extn_value']
    #         # print(sct_bytes.hex())
    #         # parse_sct(sct_bytes)
    #         # print(sct_bytes)
