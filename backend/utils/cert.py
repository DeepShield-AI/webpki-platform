
'''
    Utility functions for parsing X.509 Certs
'''
import os
import re
import csv
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import OrderedDict
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes as primitives_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Version,
    Name,
    DNSName,
    Certificate,
    ReasonFlags,
    ObjectIdentifier,
    AttributeNotFound,
    ExtensionNotFound,
    CertificateRevocationList,
    load_pem_x509_crl,
    load_der_x509_crl
)

'''
    This part handles certificates parsed by cryptography.x509 library
'''

def get_name_attribute(
        name : Name,
        oid : ObjectIdentifier,
        value_if_exception : any
    ) -> any:

    '''
        Edited 11/05/23
        This function also checks if one RDN has multiple attribute and value
    '''
    try:
        attributes = name.get_attributes_for_oid(oid)
        return attributes[0].value

    except (AttributeNotFound, IndexError):
        # my_logger.warn(f"Name attribute {oid} in {name} not found")
        return value_if_exception

'''
    This part handles certificates parsed by asn1crytpo library
'''
def ordered_dict_to_dict(data):
    if isinstance(data, list):
        return [ordered_dict_to_dict(i) for i in data]
    if isinstance(data, OrderedDict):
        return {k: ordered_dict_to_dict(v) for k, v in data.items()}
    return data

def dict_to_ordered_dict(data):
    if isinstance(data, list):
        return [dict_to_ordered_dict(i) for i in data]
    if isinstance(data, dict):
        return OrderedDict((k, dict_to_ordered_dict(v)) for k, v in data.items())
    return data

# Extract domain from given URL
def domain_extract(url : str):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return None

def is_domain_match(source_domain : str, dest_domain : str):
    # if wilicard domain, convert to regular expression representing the whole
    pattern = dest_domain.replace(".", r"\.").replace("*", ".*")
    # pattern = pattern.replace("[", "\[").replace("]", "\]")
    # pattern = pattern.replace("(", "\(").replace(")", "\)")
    pattern = f"^{pattern}$"

    if bool(re.match(pattern, source_domain)) == False:
        # my_logger.warn(f"{pattern} and {source_domain} does not match...")
        return False
    return True

def utc_time_diff_in_days(first : datetime, second : datetime) -> int:
    # return first - second in days
    time_difference = first - second
    return time_difference.days

def check_local_domain(domain : str) -> bool:
    return "local" in domain

def check_local_ip(ip : str) -> bool:
    return True

# the standard sha came from DER format!!!
def get_cert_sha256_hex_from_object(cert : Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()

# this does not indicate input format
def get_sha256_hex_from_str(obj : str) -> str:
    return hashlib.sha256(obj.encode()).hexdigest()

# this does not indicate input format
def get_sha256_hex_from_bytes(obj : bytes) -> str:
    return hashlib.sha256(obj).hexdigest()

# Certificate Policy Dict
# The input file comes from Zmap
class CertificatePolicyLookup():
    def __init__(self, input_path=os.path.join(os.path.dirname(__file__), r"../../data/cert_policies/certificate_policies.csv")) -> None:
        self.policy_look_up_dict = {}

        with open(input_path, 'r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                policy_oid = row[0]
                policy_type = 0

                if row[6]:
                    # dv
                    policy_type |= 1
                if row[7]:
                    # ov
                    policy_type |= 2
                if row[8]:
                    # ev
                    policy_type |= 4
                if row[9]:
                    # iv
                    policy_type |= 8

                self.policy_look_up_dict[policy_oid] = policy_type

# a = CertificatePolicyLookup()
# print(a.policy_look_up_dict)

# convert base64 cert to PEM format
def base64_to_pem(certificate_base64):
    # 将 Base64 数据分割为每 64 个字符一行
    formatted_certificate = "\n".join([certificate_base64[i:i+64] for i in range(0, len(certificate_base64), 64)])
    # 添加 PEM 头和尾
    pem_certificate = f"-----BEGIN CERTIFICATE-----\n{formatted_certificate}\n-----END CERTIFICATE-----"
    return pem_certificate

def read_multiple_pem_certs_from_file(pem_file):
    with open(pem_file, 'r') as f:
        cert_data = f.read()

    pem_list = []
    certificates = cert_data.split("-----END CERTIFICATE-----\n")
    for cert in certificates:
        if "-----BEGIN CERTIFICATE-----" in cert:
            cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
            pem_list.append(cert)
    return pem_list

def is_issuer(cert_to_check_pem : str, issuer_cert_pem : str):
    """
        验证 cert_to_check 是否由 issuer_cert 颁发，并验证签名。
        :param cert_to_check_pem: 目标证书的 PEM 编码
        :param issuer_cert_pem: 颁发者证书的 PEM 编码
        :return: 如果 issuer_cert 是 cert_to_check 的颁发者，并且签名验证通过，则返回 True，否则返回 False
    """
    # 加载目标证书和颁发者证书
    try:
        cert_to_check = load_pem_x509_certificate(cert_to_check_pem.encode('utf-8'), default_backend())
        issuer_cert = load_pem_x509_certificate(issuer_cert_pem.encode('utf-8'), default_backend())
    except Exception as e:
        return False
    
    # 比较目标证书的颁发者（issuer）和颁发者证书的主题（subject）
    if cert_to_check.issuer != issuer_cert.subject:
        return False
    
    # 使用颁发者证书的公钥来验证目标证书的签名
    try:
        # 获取颁发者证书的公钥
        issuer_public_key = issuer_cert.public_key()
        
        # 针对不同的签名算法执行相应的验证
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # RSA 签名验证
            issuer_public_key.verify(
                cert_to_check.signature,  # 目标证书的签名
                cert_to_check.tbs_certificate_bytes,  # 目标证书的签名前部分（tbs_certificate）
                padding.PKCS1v15(),  # 使用 PKCS1v15 填充（适用于 RSA）
                hashes.SHA256()  # 使用 SHA256 哈希算法
            )
        
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            # ECDSA 签名验证
            issuer_public_key.verify(
                cert_to_check.signature,  # 目标证书的签名
                cert_to_check.tbs_certificate_bytes,  # 目标证书的签名前部分（tbs_certificate）
                ec.ECDSA(hashes.SHA256())  # 使用 ECDSA 和 SHA256 哈希算法
            )
        
        elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
            # ED25519 签名验证
            issuer_public_key.verify(
                cert_to_check.signature,  # 目标证书的签名
                cert_to_check.tbs_certificate_bytes  # 目标证书的签名前部分（tbs_certificate）
            )
        
        else:
            raise ValueError("不支持的公钥类型")
        
        # 如果没有异常，返回 True
        return True
    
    except Exception as e:
        # 验证失败，返回 False
        print(f"签名验证失败: {e}")
        return False
