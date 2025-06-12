
import os
import json
import redis
import hashlib
import base64
from datetime import datetime
from collections import OrderedDict
import subprocess
import tempfile

from backend.config.analyze_config import AnalyzeConfig
from backend.config.path_config import ZLINT_PATH
from backend.celery.celery_app import celery_app
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.utils.exception import *
from backend.analyzer.utils import enqueue_result, stream_by_id, stream_by_cert_hash
from backend.utils.cert import get_cert_sha256_hex_from_str
from backend.celery.celery_db_pool import engine_cert

accepted_cipher_list = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
]


@celery_app.task
def build_all_from_table(output_dir: str) -> str:
    for row in stream_by_id("tlshandshake"):
        web_security_analyze.delay(row, output_dir)
    return True


@celery_app.task
def web_security_analyze(row: list, output_dir: str) -> str:
    enqueue_result(_web_security_analyze(row, output_dir))
    return True


def _web_security_analyze(row: list, output_dir: str) -> str:

    domain = row[1] # domain could be none
    ip = row[2]
    host: str = domain if domain else ip
    error_code = set()
    tls_cipher = row[-3]
    tls_version = row[-4]
    cert_hash_list = json.loads(row[-2])

    try:
        # 1. check for https deployment
        if not tls_version and not tls_cipher and not cert_hash_list:
            error_code.add("no_https")
            raise Exception("No TLS info avaliable")

        # 2. check for TLS version
        # 769	0x0301	TLS 1.0
        # 770	0x0302	TLS 1.1
        # 771	0x0303	TLS 1.2
        # 772	0x0304	TLS 1.3
        if tls_version != "771" and tls_version != "772":
            error_code.add("weak_tls_version")

        # 3. check for TLS cipher
        if tls_cipher not in accepted_cipher_list:
            error_code.add("weak_tls_cipher")

        assert(cert_hash_list)
        conn = engine_cert.raw_connection()
        cursor = conn.cursor()

        placeholders = ','.join(['%s'] * len(cert_hash_list))
        query = f"""
            SELECT * FROM cert
            WHERE cert_hash IN ({placeholders})
        """
        cursor.execute(query, cert_hash_list)
        all_rows = cursor.fetchall()

        # 用 dict 映射 cert_hash 到结果
        hash_to_row = {r[0]: r[1] for r in all_rows}  # 假设 cert_hash 是第一列
        cursor.close()

        leaf_cert: str = hash_to_row[cert_hash_list[0]]

        try:
            parsed_leaf = PEMParser.parse_native(leaf_cert)
            parsed_leaf: PEMResult = PEMParser.parse_pem_cert(leaf_cert)
        except Exception:
            raise ParseError

        # 4. hostname mismatch
        if host not in parsed_leaf.subject:
            wildcard_host = ".".join(["*"] + host.split(".")[1:])
            if wildcard_host not in parsed_leaf.subject:
                error_code.add("hostname_mismatch")

        # 5. check expired certs
        date_obj = datetime.strptime(parsed_leaf.not_after, "%Y-%m-%d-%H-%M-%S")
        now = datetime.now()
        if date_obj < now:
            error_code.add("expired_certs")

        # 6. self-signed certs
        if parsed_leaf.self_signed:
            error_code.add("self_signed_certs")

        # 7. check for chain success
        ca_subject_sha_set = set()
        for ca_cert_hash in cert_hash_list[1:]:
            ca_cert = hash_to_row[ca_cert_hash]
            parsed_ca: PEMResult = PEMParser.parse_pem_cert(ca_cert)
            ca_subject_sha_set.add(parsed_ca.subject_sha)

        if parsed_leaf.issuer_sha not in ca_subject_sha_set:
            error_code.add("chain_not_verified")

        # 8. check sig and encrypt alg
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
            temp_cert_file.write(leaf_cert.encode())
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
            for name, result in zlint_output.items():
                if result["result"] in ["warn", "error", "fatal"]:
                    error_code.add("weak_cipher")

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
            for name, result in zlint_output.items():
                if result["result"] in ["warn", "error", "fatal"]:
                    error_code.add("weak_hash")

        except RuntimeError as e:
            print(e)
            error_code.add("cert_broke")

        finally:
            try:
                os.unlink(temp_cert_path)
            except OSError:
                pass

    except ParseError:
        error_code.add("cert_broke")

    except Exception as e:
        primary_logger.error(e)

    finally:
        return {
            "flag" : AnalyzeConfig.TASK_WEB_SECURITY,
            "out_dir" : output_dir,
            "domain" : domain,
            "ip" : ip,
            "tls_version" : tls_version,
            "tls_cipher" : tls_cipher,
            "cert_hash_list" : cert_hash_list,
            "error_code" : list(error_code)
        }
