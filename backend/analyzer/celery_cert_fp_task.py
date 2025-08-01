
# celery_cert_fp_task.py

'''
    Reference "https://github.com/zzma/asn1-fingerprint"
'''
import hashlib
import base64
from datetime import datetime
from collections import OrderedDict

from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert
from backend.logger.logger import primary_logger
from backend.parser.asn1_parser import ASN1Parser
from backend.utils.exception import *
from backend.utils.type import sort_dict_by_key, sort_list_by_key
from backend.utils.cert import CertificatePolicyLookup, utc_time_diff_in_days, get_sha256_hex_from_str


@celery_app.task
def build_all_from_table(cert_table: str) -> str:
    for row in stream_by_id(engine_cert.raw_connection(), cert_table):
        build_cert_fp_from_row.delay(row)


@celery_app.task
def build_cert_fp_from_row(row: list):
    fp = _build_cert_fp(row[2])
    enqueue_result({
        "flag": AnalyzeConfig.TASK_CERT_FP,
        "id" : row[0],
        "fp" : fp,
        "fp_sha256" : get_sha256_hex_from_str(str(fp))
    })
    return True


def _build_cert_fp(der_bytes: bytes) -> str:
    return ASN1StructFP.build_fp(der_bytes)

class ASN1StructFP:
    # Static type indicators
    VERSION = 0
    DATETIME = 1
    OBJ_ID = 2
    URL_DOMAIN = 3
    ID_DATA = 4

    LONG_NUMBER = 0
    ID_NUMBER = 1

    # Static policy lookup table
    policy_lookup = CertificatePolicyLookup()

    @staticmethod
    def build_fp(der_bytes: bytes) -> tuple[str, str]:

        parsed_cert = ASN1Parser.parse_der_native(der_bytes)
        if type(parsed_cert) != OrderedDict:
            primary_logger.error("Certificate should be passed in OrderDict type")
            return ""

        fp_raw = []
        ASN1StructFP.fp_recursive(parsed_cert["tbs_certificate"], fp_raw)
        return fp_raw

    @staticmethod
    def fp_recursive(obj: any, current_fp_raw: list, obj_type: int = None) -> None:
        # primary_logger.debug(current_fp_raw)
        # primary_logger.debug(type(obj))
        # primary_logger.debug(obj_type)
        if obj is None:
            current_fp_raw.append("")
            return

        if isinstance(obj, OrderedDict):
            for key, value in sort_dict_by_key(obj).items():
                if key == "version":
                    ASN1StructFP.fp_recursive(value, current_fp_raw, ASN1StructFP.VERSION)
                elif key == "serial_number":
                    ASN1StructFP.fp_recursive(value, current_fp_raw, ASN1StructFP.LONG_NUMBER)
                elif key == "signature" or key == "algorithm":
                    ASN1StructFP.fp_recursive(value["algorithm"], current_fp_raw, ASN1StructFP.OBJ_ID)
                    ASN1StructFP.fp_recursive(value["parameters"], current_fp_raw, ASN1StructFP.OBJ_ID)
                elif key == "issuer":
                    continue
                elif key == "validity":
                    ASN1StructFP.fp_recursive((value["not_after"], value["not_before"]), current_fp_raw, ASN1StructFP.DATETIME)
                elif key == "subject":
                    continue
                elif key == "subject_public_key_info":
                    ASN1StructFP.fp_recursive(value, current_fp_raw)
                elif key == "public_key":
                    try:
                        ASN1StructFP.fp_recursive(value["modulus"], current_fp_raw, ASN1StructFP.LONG_NUMBER)
                        ASN1StructFP.fp_recursive(value["public_exponent"], current_fp_raw, ASN1StructFP.ID_NUMBER)
                    except TypeError:
                        ASN1StructFP.fp_recursive(value, current_fp_raw, ASN1StructFP.LONG_NUMBER)
                elif key in ["issuer_unique_id", "subject_unique_id"]:
                    ASN1StructFP.fp_recursive(value, current_fp_raw)
                elif key == "extensions":
                    if not value: continue
                    for extension in value:
                        ASN1StructFP.fp_recursive(bool(extension["critical"]), current_fp_raw)
                        extn_id = extension["extn_id"]
                        extn_val = extension["extn_value"]
                        try:
                            if extn_id in ["key_usage", "extended_key_usage"]:
                                for flag in sorted(extn_val):
                                    ASN1StructFP.fp_recursive(flag, current_fp_raw, ASN1StructFP.OBJ_ID)
                            elif extn_id == "basic_constraints":
                                ASN1StructFP.fp_recursive(extn_val["ca"], current_fp_raw)
                                ASN1StructFP.fp_recursive(extn_val["path_len_constraint"], current_fp_raw, ASN1StructFP.ID_NUMBER)
                            elif extn_id == "key_identifier":
                                ASN1StructFP.fp_recursive(extn_val, current_fp_raw, ASN1StructFP.ID_DATA)
                            elif extn_id == "authority_key_identifier":
                                ASN1StructFP.fp_recursive(extn_val["key_identifier"], current_fp_raw, ASN1StructFP.ID_DATA)
                                ASN1StructFP.fp_recursive(extn_val["authority_cert_serial_number"], current_fp_raw, ASN1StructFP.ID_DATA)
                            elif extn_id == "authority_information_access":
                                for aia in sort_list_by_key(extn_val, "access_method"):
                                    ASN1StructFP.fp_recursive(aia["access_method"], current_fp_raw, ASN1StructFP.OBJ_ID)
                                    ASN1StructFP.fp_recursive(aia["access_location"], current_fp_raw, ASN1StructFP.URL_DOMAIN)
                            elif extn_id == "crl_distribution_points":
                                for crl in extn_val:
                                    for url in sorted(crl["distribution_point"]):
                                        ASN1StructFP.fp_recursive(url, current_fp_raw, ASN1StructFP.URL_DOMAIN)
                                    if crl["reasons"]:
                                        for reason in sorted(crl["reasons"]):
                                            ASN1StructFP.fp_recursive(reason, current_fp_raw, ASN1StructFP.OBJ_ID)
                            elif extn_id == "certificate_policies":
                                for policy in sort_list_by_key(extn_val, "policy_identifier"):
                                    try:
                                        policy_flag = ASN1StructFP.policy_lookup.policy_look_up_dict[policy["policy_identifier"]]
                                        ASN1StructFP.fp_recursive(policy_flag, current_fp_raw, ASN1StructFP.ID_NUMBER)
                                    except KeyError:
                                        primary_logger.warning(f"Policy {policy['policy_identifier']} not found.")
                                        ASN1StructFP.fp_recursive(policy["policy_identifier"], current_fp_raw, ASN1StructFP.OBJ_ID)
                                    for qualifier in sort_list_by_key(policy["policy_qualifiers"], "policy_qualifier_id"):
                                        ASN1StructFP.fp_recursive(qualifier["policy_qualifier_id"], current_fp_raw, ASN1StructFP.OBJ_ID)
                                        ASN1StructFP.fp_recursive(qualifier["qualifier"], current_fp_raw, ASN1StructFP.URL_DOMAIN)
                        except Exception as e:
                            primary_logger.warning(f"Failed to process extension {extn_id}: {e}")
                else:
                    primary_logger.warning(f"Unsupported field in certificate: {key}")

        # note: type bool will pass for both isinstance(bool) and isinstance(int)...
        elif isinstance(obj, bool):
            current_fp_raw.append(int(obj))

        elif isinstance(obj, int):
            if obj_type == ASN1StructFP.LONG_NUMBER:
                current_fp_raw.append(obj.bit_length())
            elif obj_type == ASN1StructFP.ID_NUMBER:
                current_fp_raw.append(obj)
            else:
                primary_logger.error(f"{obj} has the type {obj_type}")
                raise UnsupportedIntegerTypeError(obj_type)

        elif isinstance(obj, str):
            if obj_type == ASN1StructFP.VERSION:
                current_fp_raw.append(obj[1])
            elif obj_type == ASN1StructFP.DATETIME:
                dt = datetime.fromisoformat(obj)
                current_fp_raw.append(dt.timestamp())
            elif obj_type in [ASN1StructFP.OBJ_ID, ASN1StructFP.ID_DATA]:
                current_fp_raw.append(len(obj))
            elif obj_type == ASN1StructFP.URL_DOMAIN:
                if obj.startswith("http://"):
                    current_fp_raw.append(len(obj[7:]))
                elif obj.startswith("https://"):
                    current_fp_raw.append(len(obj[8:]))
                else:
                    current_fp_raw.append(len(obj))
            else:
                raise UnsupportedStringTypeError(obj_type)

        elif isinstance(obj, (bytearray, bytes)):
            try:
                val = int(base64.b64encode(obj).decode("utf-8"))
                ASN1StructFP.fp_recursive(val, current_fp_raw, ASN1StructFP.LONG_NUMBER)
            except ValueError:
                s = base64.b64encode(obj).decode("utf-8")
                ASN1StructFP.fp_recursive(s, current_fp_raw, ASN1StructFP.ID_DATA)

        elif isinstance(obj, tuple):
            current_fp_raw.append(utc_time_diff_in_days(obj[0], obj[1]))

        else:
            raise TypeError(f"Unsupported certificate field type: {type(obj)}")

    @staticmethod
    def fp_hash(fp_raw: str) -> str:
        return hashlib.sha256(fp_raw.encode()).hexdigest()
