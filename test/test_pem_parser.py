
import sys
sys.path.append(r"D:\global_ca_monitor")
from app.parser.pem_parser import PEMParser
import struct
import binascii
import base64

# 解析 Signed Certificate Timestamp (SCT)
def parse_sct(sct):
    # 解析 version (1 byte)
    version = sct[0]
    
    # 解析 LogID (32 bytes)
    hex_log_id = sct[1:33].hex()
    
    # 解析 timestamp (8 bytes)
    timestamp = struct.unpack('>Q', sct[33:41])[0]
    
    # Convert hex to binary
    binary_log_id = binascii.unhexlify(hex_log_id)

    # Convert binary to Base64
    base64_log_id = base64.b64encode(binary_log_id).decode('utf-8')

    # 输出结果
    print("Version:", version)
    print("LogID:", base64_log_id)
    print("Timestamp:", timestamp)


with open(r'test_certs/tsinghua.edu.cn_single.pem', 'r') as f:
    data = f.read()

    pem_parser = PEMParser()
    cert = pem_parser.parse_native(data)
    extensions = cert['tbs_certificate']['extensions']

    for ext in extensions:
        ext_id = ext['extn_id']
        if ext_id == 'signed_certificate_timestamp_list':
            sct_bytes = ext['extn_value']
            print(sct_bytes.hex())
            parse_sct(sct_bytes)
