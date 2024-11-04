
'''
    Reference "https://github.com/zzma/asn1-fingerprint"
'''

import base64
import hashlib
from datetime import datetime
from collections import OrderedDict
from ..utils.exception import *
from ..logger.logger import my_logger
from ..utils.cert import CertificatePolicyLookup, utc_time_diff_in_days
from ..utils.type import sort_dict_by_key, sort_list_by_key

class ASN1StructFP():

    def __init__(self) -> None:

        # string types
        self.VERSION = 0
        self.DATETIME = 1
        self.OBJ_ID = 2
        self.URL_DOMAIN = 3
        self.ID_DATA = 4

        # int types
        self.LONG_NUMBER = 0
        self.ID_NUMBER = 1

        # policy lookup
        self.policy_lookup = CertificatePolicyLookup()


    def build_fp(self, parsed_cert : OrderedDict) -> tuple[str, str]:

        if type(parsed_cert) != OrderedDict:
            my_logger.error("Certificate should be passed in OrderDict type")
            return ""

        fp_raw = []
        self.fp_recursive(parsed_cert["tbs_certificate"], fp_raw)
        fp_raw = [str(item) for item in fp_raw]
        fp_raw_string = ",".join(fp_raw)
        return self.fp_hash(fp_raw_string), fp_raw


    def fp_recursive(self, obj : any, current_fp_raw : list, obj_type : int = None) -> None:

        # The field is None
        if obj == None:
            current_fp_raw.append("")
            return

        # Compound item
        if type(obj) == OrderedDict:

            # Must be sorted to keep the field order, make hash consistent
            for key, value in sort_dict_by_key(obj).items():

                if key == "version":
                    self.fp_recursive(value, current_fp_raw, self.VERSION)
                elif key == "serial_number":
                    self.fp_recursive(value, current_fp_raw, self.LONG_NUMBER)
                elif key == "signature" or key == "algorithm":
                    self.fp_recursive(value["algorithm"], current_fp_raw, self.OBJ_ID)
                    self.fp_recursive(value["parameters"], current_fp_raw, self.OBJ_ID)
                elif key == "issuer":
                    # currently skip issuer
                    continue
                elif key == "validity":
                    # not before and not after are passed as a tuple string
                    self.fp_recursive((value["not_after"], value["not_before"]), current_fp_raw, self.DATETIME)
                elif key == "subject":
                    # currently skip subject
                    continue
                elif key == "subject_public_key_info":
                    self.fp_recursive(value, current_fp_raw)
                elif key == "public_key":
                    try:
                        # rsa key
                        self.fp_recursive(value["modulus"], current_fp_raw, self.LONG_NUMBER)
                        self.fp_recursive(value["public_exponent"], current_fp_raw, self.ID_NUMBER)
                    except TypeError:
                        # ec key
                        self.fp_recursive(value, current_fp_raw, self.LONG_NUMBER)
                elif key == "issuer_unique_id":
                    self.fp_recursive(value, current_fp_raw)
                elif key == "subject_unique_id":
                    self.fp_recursive(value, current_fp_raw)

                # Below are extensions
                # Note: we only select some important extensions
                # For any other extensions, we only add its critical flag into the current_fp_raw
                elif key == "extensions":
                    for extension in value:
                        # Critical flag
                        self.fp_recursive(extension["critical"], current_fp_raw)

                        if extension["extn_id"] == "key_usage" or extension["extn_id"] == "extended_key_usage":
                            for flag in sorted(extension["extn_value"]):
                                self.fp_recursive(flag, current_fp_raw, self.OBJ_ID)
                        elif extension["extn_id"] == "basic_constraints":
                            self.fp_recursive(extension["extn_value"]["ca"], current_fp_raw)
                            self.fp_recursive(extension["extn_value"]["path_len_constraint"], current_fp_raw, self.ID_NUMBER)
                        elif extension["extn_id"] == "name_constraints":
                            # currently pass, add back if necessary
                            pass
                        elif extension["extn_id"] == "key_identifier":
                            self.fp_recursive(extension["extn_value"], current_fp_raw, self.ID_DATA)
                        elif extension["extn_id"] == "authority_key_identifier":
                            self.fp_recursive(extension["extn_value"]["key_identifier"], current_fp_raw, self.ID_DATA)
                            # Skip the authority names
                            # self.fp_recursive(extension["extn_value"]["authority_cert_issuer"], current_fp_raw, self.ID_DATA)
                            self.fp_recursive(extension["extn_value"]["authority_cert_serial_number"], current_fp_raw, self.ID_DATA)
                        elif extension["extn_id"] == "authority_information_access":
                            for aia in sort_list_by_key(extension["extn_value"], "access_method"):
                                self.fp_recursive(aia["access_method"], current_fp_raw, self.OBJ_ID)
                                self.fp_recursive(aia["access_location"], current_fp_raw, self.URL_DOMAIN)
                        elif extension["extn_id"] == "crl_distribution_points":
                            for crl in sorted(extension["extn_value"]):
                                for url in sorted(crl["distribution_point"]):
                                    self.fp_recursive(url, current_fp_raw, self.URL_DOMAIN)
                                if crl["reasons"]:
                                    for reason in sorted(crl["reasons"]):
                                        self.fp_recursive(reason, current_fp_raw, self.OBJ_ID)
                                # Skip crl issuer name
                                # self.fp_recursive(crl["crl_issuer"], current_fp_raw, self.ID_DATA)
                        elif extension["extn_id"] == "subject_alt_name":
                            # Skip all the SAN contents
                            pass
                        elif extension["extn_id"] == "certificate_policies":
                            for policy in sort_list_by_key(extension["extn_value"], "policy_identifier"):
                                try:
                                    policy_flag = self.policy_lookup.policy_look_up_dict[policy["policy_identifier"]]
                                    self.fp_recursive(policy_flag, current_fp_raw, self.ID_NUMBER)
                                except KeyError:
                                    my_logger.warning(f"Policy {policy['policy_identifier']} does not exist in the dictionary")
                                    self.fp_recursive(policy_flag, current_fp_raw, self.OBJ_ID)
                                # policy qualifiers
                                for qualifier in sort_list_by_key(policy["policy_qualifiers"], "policy_qualifier_id"):
                                    self.fp_recursive(qualifier["policy_qualifier_id"], current_fp_raw, self.OBJ_ID)
                                    self.fp_recursive(qualifier["qualifier"], current_fp_raw, self.URL_DOMAIN)
                        elif extension["extn_id"] == "signed_certificate_timestamp_list" or extension["extn_id"] == "precertificate_signed_certificate_timestamp_list":
                            # CA does not always put the reissued certificate into the same CT log
                            # Based on my observation, it depends on the issued time and validity
                            # so we pass this extension
                            pass
                        elif extension["extn_id"] == "precertificate_poison":
                            # also, don't care about the precertificate_poision here
                            pass
                        else:
                            my_logger.warning(f"Unsupported extension in certificate: {extension['extn_id']}")
                            pass
                else:
                    my_logger.warning(f"Unsupported field in certificate: {key}")
                    pass

        elif type(obj) == int:
            if obj_type == self.LONG_NUMBER:
                current_fp_raw.append(obj.bit_length())
            elif obj_type == self.ID_NUMBER:
                current_fp_raw.append(obj)
            else:
                raise UnsupportedIntegerTypeError(obj_type)

        elif type(obj) == str:
            if obj_type == self.VERSION:
                current_fp_raw.append(obj[1])
            elif obj_type == self.DATETIME:
                obj_datetime = datetime.fromisoformat(obj)
                current_fp_raw.append(obj_datetime.timestamp())
            elif obj_type == self.OBJ_ID:
                current_fp_raw.append(obj)
            elif obj_type == self.URL_DOMAIN:
                if obj.startswith("http://"):
                    current_fp_raw.append(len(obj[7:]))
                elif obj.startswith("https://"):
                    current_fp_raw.append(len(obj[8:]))
                else:
                    current_fp_raw.append(len(obj[:]))
            elif obj_type == self.ID_DATA:
                current_fp_raw.append(len(obj))
            else:
                raise UnsupportedStringTypeError(obj_type)

        elif type(obj) == bytearray or type(obj) == bytes:
            try:
                # convert to int and parse again
                obj_int = int(base64.b64encode(obj).decode('utf-8'))
                self.fp_recursive(obj_int, current_fp_raw, self.LONG_NUMBER)
            except ValueError:
                # bytes not represent int, but str
                obj_str = base64.b64encode(obj).decode('utf-8')
                self.fp_recursive(obj_str, current_fp_raw, self.ID_DATA)

        elif type(obj) == tuple:
            # only for validity
            current_fp_raw.append(utc_time_diff_in_days(obj[0], obj[1]))

        elif type(obj) == bool:
            current_fp_raw.append(int(obj))

        else:
            print(obj)
            raise TypeError(f"Improper certificate object type: {type(obj)}")


    def fp_hash(self, fp_raw : str) -> str:
        # currently, we just use simple sha256 for final fp
        sha256_hash = hashlib.sha256(fp_raw.encode())
        sha256_hex = sha256_hash.hexdigest()
        return sha256_hex

