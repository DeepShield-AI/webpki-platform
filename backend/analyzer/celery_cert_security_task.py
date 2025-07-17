
import os
import json
import tempfile
import ipaddress
import subprocess

from datetime import datetime, timezone
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.config.analyze_config import AnalyzeConfig
from backend.config.path_config import ZLINT_PATH, ROOT_DIR
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import ASN1Parser

@celery_app.task
def build_all_from_table(output_dir: str) -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "cert"):
        cert_security_analyze.delay(row, output_dir)
    return True


@celery_app.task
def cert_security_analyze(row: list, output_dir: str) -> str:
    analysis_result = _cert_security_analyze(row[1], row[2])
    analysis_result["id"] = row[0]
    analysis_result["out_dir"] = output_dir
    enqueue_result(analysis_result)
    return True


def _cert_security_analyze(sha256: str, cert_der: str) -> str:

    try:
        error_code = set()
        error_info = {}
        parsed: dict = ASN1Parser.parse_native_pretty_der(cert_der)
        # primary_logger.debug(parsed)

        # 1. check expired certs
        not_before = parsed['tbs_certificate']['validity']['not_before']
        not_after = parsed['tbs_certificate']['validity']['not_after']

        now = datetime.now(timezone.utc)
        if not_after < now:
            error_code.add("expired")

        # 2. check validity time
        validity = (not_after - not_before).days
        if validity > 398:
            error_code.add("validity_too_long")
            error_info["validity_too_long"] = validity

        # 3. check sig and encrypt alg
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
            temp_cert_file.write(ASN1Parser.der2pem(cert_der).encode())
            temp_cert_path = temp_cert_file.name

        try:
            result = subprocess.run(
                [
                    ZLINT_PATH,
                    "-includeNames=e_rsa_mod_less_than_2048_bits,e_dsa_shorter_than_2048_bits",
                    temp_cert_path
                    # "-includeNames=e_rsa_mod_less_than_2048_bits,w_rsa_mod_factors_smaller_than_752,e_dsa_shorter_than_2048_bits,e_old_sub_cert_rsa_mod_less_than_1024_bits"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

            zlint_output = json.loads(result.stdout)
            # primary_logger.debug(zlint_output)
            for name, result in zlint_output.items():
                if result["result"] in ["warn", "error", "fatal"]:
                    error_code.add("weak_rsa")

            # next
            result = subprocess.run(
                [
                    ZLINT_PATH,
                    "-includeNames=e_sub_cert_or_sub_ca_using_sha1,e_signature_algorithm_not_supported",
                    temp_cert_path
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

            zlint_output = json.loads(result.stdout)
            # primary_logger.debug(zlint_output)
            for name, result in zlint_output.items():
                if result["result"] in ["warn", "error", "fatal"]:
                    error_code.add("weak_hash")

        except RuntimeError:
            error_code.add("not_asn1")
        finally:
            try:
                os.unlink(temp_cert_path)
            except OSError:
                pass

        # 4. self-signed cert
        issuer = parsed['tbs_certificate']['issuer']
        subject = parsed['tbs_certificate']['subject']
        if issuer == subject:
            error_code.add("self_signed")

        # 5. if cert is deployed on any ip that is in abuseipdb or drop
        ips = find_ip_by_cert_sha256(sha256)
        filtered_ips = filter_abuse_ip(ips)
        if filtered_ips:
            error_code.add("abuse_ip")
            error_info["abuse_ip"] = filtered_ips

        filtered_ips = filter_drop_ip(ips)
        if filtered_ips:
            error_code.add("DROP")
            error_info["DROP"] = filtered_ips

        # 6 version
        version = parsed['tbs_certificate']['version']
        if version != "v3":
            error_code.add("wrong_version")
            error_info["wrong_version"] = version

        # 7 key usage
        extensions = parsed['tbs_certificate']["extensions"]
        error_info["wrong_key_usage"] = []
        error_info["no_revoke"] = []

        def find_ext(name):
            if extensions:
                for e in extensions:
                    if e["extn_id"] == name:
                        return e
            return None

        if not find_ext("extended_key_usage"):
            error_code.add("wrong_key_usage")
            error_info["wrong_key_usage"].append("No Ext Key Usage")
        else:
            if "server_auth" not in find_ext("extended_key_usage")["extn_value"]:
                error_code.add("wrong_key_usage")
                error_info["wrong_key_usage"].append("No Server Auth")

        if not find_ext("key_usage"):
            error_code.add("wrong_key_usage")
            error_info["wrong_key_usage"].append("No Key Usage")
        else:
            if "digital_signature" not in find_ext("key_usage")["extn_value"]:
                error_code.add("wrong_key_usage")
                error_info["wrong_key_usage"].append("No Digital Sig")

        # 8 revoke info
        if not find_ext("crl_distribution_points"):
            error_code.add("no_revoke")
            error_info["no_revoke"].append("No CRL")
        else:
            if not find_ext("crl_distribution_points")["extn_value"]:
                error_code.add("wrong_key_usage")
                error_info["no_revoke"].append("No CRL")

        if not find_ext("authority_information_access"):
            error_code.add("no_revoke")
            error_info["no_revoke"].append("No OCSP")

        # 9 SCT
        if not find_ext("signed_certificate_timestamp_list"):
            error_code.add("no_sct")
            error_info["no_sct"] = "No SCT"

    except Exception as e:
        primary_logger.error(e)
        error_code.add("not_asn1")

    finally:
        # only add cert node if the cert structure is broken
        return {
            "flag" : AnalyzeConfig.TASK_CERT_SECURITY,
            "error_code" : list(error_code),
            "error_info" : error_info
        }


# go through the cert table
def find_ip_by_cert_sha256(cert_sha256):

    conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    query = f"""
        SELECT * FROM tlshandshake
        WHERE JSON_CONTAINS (cert_sha256_list, %s)
        LIMIT 200
    """
    cursor.execute(query, (json.dumps([cert_sha256]), ))
    rows = cursor.fetchall()
    cursor.close()

    return [row[2] for row in rows]


def filter_abuse_ip(ip_set):

    with open(os.path.join(ROOT_DIR, "data/abuse_ip_db/blacklist_20250529.json"), "r", encoding='utf-8-sig') as bl:
        abuse_records = json.load(bl)
        data = abuse_records["data"]

        ip_abuse_data = {}
        for record in data:
            ip_abuse_data[record["ipAddress"]] = record["countryCode"]

    with open(os.path.join(ROOT_DIR, "data/abuse_ip_db/blacklist_20250530.json"), "r", encoding='utf-8-sig') as bl:
        abuse_records = json.load(bl)
        data = abuse_records["data"]

        for record in data:
            ip_abuse_data[record["ipAddress"]] = record["countryCode"]

    with open(os.path.join(ROOT_DIR, "data/abuse_ip_db/blacklist_plain_20250530"), "r", encoding='utf-8-sig') as bl:
        plain_ip_data = []
        for line in bl:
            plain_ip_data.append(line.strip())

    filtered_ip_set = set()
    for ip in ip_set:
        if ip in ip_abuse_data:
            filtered_ip_set.add((ip, ip_abuse_data[ip]))
        elif ip in plain_ip_data:
            filtered_ip_set.add(ip)
    return list(filtered_ip_set)


def filter_drop_ip(ip_set):
    with open(os.path.join(ROOT_DIR, "data/drop_v4/DROP_v4_20250530.json"), "r", encoding='utf-8-sig') as bl:
        drop_data = {}
        for line in bl:
            try:
                _json = json.loads(line)
                # print(_json)
                drop_data[ipaddress.ip_network(_json["cidr"])] = _json["sblid"]
            except:
                pass
    filtered_ip_set = []
    for ip in ip_set:
        _ip = ipaddress.ip_address(ip)
        for _network in drop_data:
            if _ip in _network:
                filtered_ip_set.append((ip, drop_data[_network]))

    return filtered_ip_set
