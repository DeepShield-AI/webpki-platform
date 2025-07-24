
import csv
import base64
import hashlib
from backend.parser.asn1_parser import PEMParser

input_file = '/var/lib/mysql-files/cert.csv'
output_file = '/var/lib/mysql-files/converted.csv'

with open(input_file, newline='', encoding='utf-8') as csv_in, \
     open(output_file, 'w', newline='', encoding='utf-8') as csv_out:
    
    reader = csv.reader(csv_in)
    writer = csv.writer(csv_out)
    
    writer.writerow(['old_cert_hash', 'new_cert_hash', 'cert_der_base64'])  # 输出列
    
    for row in reader:
        old_hash, pem_string = row
        try:
            pem = pem_string.replace('\\\n', '\n')

            # 转 DER 格式
            der_bytes = PEMParser.pem_to_der(pem)
            # 计算新 SHA256
            new_hash = hashlib.sha256(der_bytes).hexdigest()
            # Base64 编码 DER
            der_b64 = base64.b64encode(der_bytes).decode()
            # 写入新 CSV
            writer.writerow([old_hash, new_hash, der_b64])
        except Exception as e:
            print(pem)
            print(f"处理失败: {old_hash}，原因: {e}")
