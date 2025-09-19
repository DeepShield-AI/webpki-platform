import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import os
import glob

private_keys_folder = r'/home/tianyuz23/data/houseofkeys/private_keys'
rsa_known_keys = []
key_files = glob.glob(os.path.join(private_keys_folder, "*.key"))
for key_file in key_files:
    # 读取私钥文件
    with open(key_file, 'r') as f:
        key_content = f.read().strip()

        private_key = None
        key_name = os.path.basename(key_file)
        
        try:
            # 尝试作为PEM格式加载
            private_key = serialization.load_pem_private_key(
                key_content.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
        except ValueError:
            try:
                # 如果PEM格式失败，尝试作为DER格式
                with open(key_file, 'rb') as f_der:
                    der_key_bytes = f_der.read()
                private_key = serialization.load_der_private_key(
                    der_key_bytes,
                    password=None,
                    backend=default_backend()
                )
            except ValueError:
                continue
        
        # 获取私钥对应的公钥
        private_public_key = private_key.public_key()
        rsa_known_keys.append(private_public_key)
        # print(private_public_key.public_numbers().n)

def verify_cert_with_private_keys(der_bytes):
    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        cert_public_key = cert.public_key()
        
        if not isinstance(cert_public_key, rsa.RSAPublicKey):
            return False
        
        cert_pub_numbers = cert_public_key.public_numbers()
        
        for private_public_key in rsa_known_keys:
            try:
                if isinstance(private_public_key, rsa.RSAPublicKey):
                    private_pub_numbers = private_public_key.public_numbers()
                    
                    print(cert_pub_numbers.n, private_pub_numbers.n) 
                    print(cert_pub_numbers.e, private_pub_numbers.e)

                    if (cert_pub_numbers.n == private_pub_numbers.n and 
                        cert_pub_numbers.e == private_pub_numbers.e):
                        return True
            except Exception:
                continue
        
        return False
        
    except Exception:
        return False

# 使用上下文管理器确保资源正确释放
new_conn = engine_cert.raw_connection()
try:
    with open("13-id_seed.txt", "r") as input_file, open("13-vul_ids.txt", "w") as out:
        for line in input_file:
            # 去除换行符并获取ID
            cert_id = line.strip()
            print(cert_id)
            if not cert_id:
                continue
                
            with new_conn.cursor() as cursor:
                query = """
                    SELECT * from cert
                    WHERE id = %s
                """
                cursor.execute(query, (cert_id,))
                row = cursor.fetchone()

            if row:
                der_bytes = row[2]  # 假设第3列是证书数据

                if verify_cert_with_private_keys(der_bytes):
                    out.write(cert_id)
                    out.write('\n')
finally:
    new_conn.close()
    