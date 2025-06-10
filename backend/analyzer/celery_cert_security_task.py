
import os
import json
import redis
import hashlib
import base64
from datetime import datetime
from collections import OrderedDict
import subprocess
import tempfile
import ipaddress

from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.config.analyze_config import AnalyzeConfig
from backend.config.path_config import ZLINT_PATH, ROOT_DIR
from backend.celery.celery_app import celery_app
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.utils.exception import *
from backend.analyzer.utils import enqueue_result, stream_by_id, stream_by_cert_hash

@celery_app.task
def build_all_from_table(output_dir: str) -> str:
    for row in stream_by_cert_hash("cert"):
        # primary_logger.debug(row)
        cert_security_analyze.delay(row, output_dir)
    return True

@celery_app.task
def cert_security_analyze(row: list, output_dir: str) -> str:

    try:
        cert: str = row[1]
        error_code = set()
        error_info = {}
        parsed: PEMResult = PEMParser.parse_pem_cert(cert)
        # primary_logger.debug(parsed)

        # 1. check expired certs
        date_obj = datetime.strptime(parsed.not_after, "%Y-%m-%d-%H-%M-%S")
        now = datetime.now()
        if date_obj < now:
            error_code.add("expired")

        # 2. check validity time
        not_before = datetime.strptime(parsed.not_before, "%Y-%m-%d-%H-%M-%S")
        not_after = datetime.strptime(parsed.not_after, "%Y-%m-%d-%H-%M-%S")
        primary_logger.debug((not_after - not_before).days)
        if (not_after - not_before).days > 398:
            error_code.add("validity_too_long")

        # 3. check sig and encrypt alg
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
            temp_cert_file.write(cert.encode())
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
            primary_logger.debug(zlint_output)
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
            primary_logger.debug(zlint_output)
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
        if parsed.self_signed:
            error_code.add("self_signed")

        # 5. if cert is deployed on any ip that is in abuseipdb or drop
        ips = find_ip_by_cert_sha256(row[0])
        filtered_ips = filter_abuse_ip(ips)
        if filtered_ips:
            error_code.add("abuse_ip")
            error_info["abuse_ip"] = filtered_ips

        filtered_ips = filter_drop_ip(ips)
        if filtered_ips:
            error_code.add("DROP")
            error_info["DROP"] = filtered_ips

        '''
            # 5.3 version
            if str(leaf["parsed"]["version"]) != "3":
                error_code.add("wrong_version")

            # 5.4 key usage
            try:
                if not leaf["parsed"]["extensions"]["extended_key_usage"]["server_auth"]:
                    error_code.add("wrong_key_usage")
            except KeyError:
                    error_code.add("wrong_key_usage")
            try:
                if leaf["parsed"]["extensions"]["extended_key_usage"]["certificate_sign"]:
                    error_code.add("wrong_key_usage")
                if leaf["parsed"]["extensions"]["extended_key_usage"]["crl_sign"]:
                    error_code.add("wrong_key_usage")
            except:
                pass

            # 5.4 revoke info
            try:
                crl = leaf["parsed"]["extensions"]["crl_distribution_points"]
            except KeyError:
                try:
                    aia = leaf["parsed"]["extensions"]["authority_info_access"]
                except KeyError:
                    error_code.add("no_revoke")

            # 5.5 SCT
            try:
                crl = leaf["parsed"]["extensions"]["signed_certificate_timestamps"]
            except KeyError:
                error_code.add("no_sct")
        '''

    except Exception as e:
        primary_logger.error(e)
        error_code.add("not_asn1")

    finally:
        # only add cert node if the cert structure is broken
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CERT_SECURITY,
            "out_dir" : output_dir,
            "cert_hash" : row[0],
            "error_code" : list(error_code),
            "error_info" : error_info
        })

        return True


# go through the cert table
def find_ip_by_cert_sha256(cert_sha256):

    conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    query = f"""
        SELECT * FROM tlshandshake
        WHERE JSON_CONTAINS (cert_hash_list, %s)
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

    filtered_ip_set = []
    for ip in ip_set:
        if ip in plain_ip_data:
            filtered_ip_set.append(ip)
        if ip in ip_abuse_data:
            filtered_ip_set.append((ip, ip_abuse_data[ip]))
    return filtered_ip_set


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
