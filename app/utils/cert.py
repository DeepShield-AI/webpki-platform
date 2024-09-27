
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

def get_cert_sha256_hex_from_object(cert : Certificate) -> str:
    sha256_hash = hashlib.sha256(cert.public_bytes(Encoding.PEM))
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex

def get_cert_sha256_hex_from_str(cert : str) -> str:
    sha256_hash = hashlib.sha256(cert.encode())
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex

# Certificate Policy Dict
# The input file comes from Zmap
class CertificatePolicyLookup():
    def __init__(self, input_path=os.path.join(os.path.dirname(__file__), r"../data/certificate_policies.csv")) -> None:
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
