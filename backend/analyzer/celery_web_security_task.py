
import time
import redis
import json

from datetime import datetime
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.celery.celery_app import celery_app
from backend.config.analyze_config import AnalyzeConfig
from backend.logger.logger import primary_logger
from backend.parser.asn1_parser import ASN1Parser, ASN1Result
from backend.utils.exception import *

accepted_cipher_list = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
]

r = redis.Redis()

@celery_app.task
def build_all_from_table(start_id=0) -> str:
    for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake", start_id=start_id):
        web_security_analyze_from_row.delay(row)

        while True:
            if r.llen('celery') <= 10000: break
            time.sleep(1)

    return True


@celery_app.task
def web_security_analyze_from_row(row: list) -> str:
    analysis_result = _web_security_analyze(
        row[1],
        row[2],
        row[-5],
        row[-4],
        row[-3],
        json.loads(row[-2]),
        scan_time=row[3]
    )
    analysis_result["id"] = row[0]
    enqueue_result(analysis_result)
    return True


def _web_security_analyze(
        domain : str,
        ip : str,
        tls_version : str,
        tls_cipher : str,
        leaf_sha256 : str,
        chain_sha256_list : list,
        scan_time : datetime = datetime.now()
    ) -> str:

    host: str = domain if domain else ip
    error_code = set()

    try:
        # 1. check for https deployment
        # print(tls_version, tls_cipher, cert_sha256_list)
        if not tls_version and not tls_cipher and not leaf_sha256:
            error_code.add("no_https")
            raise Exception("No TLS info avaliable")

        # 2. check for TLS version
        # 769	0x0301	TLS 1.0
        # 770	0x0302	TLS 1.1
        # 771	0x0303	TLS 1.2
        # 772	0x0304	TLS 1.3
        if int(tls_version) != 771 and int(tls_version) != 772:
            error_code.add("weak_tls_version")

        # 3. check for TLS cipher
        if tls_cipher not in accepted_cipher_list:
            error_code.add("weak_tls_cipher")

        assert(leaf_sha256)
        conn = engine_cert.raw_connection()
        cursor = conn.cursor()

        sql = """
            SELECT * FROM cert
            WHERE sha256 = %s
        """
        cursor.execute(sql, (leaf_sha256,))  # 注意 tuple 格式
        row = cursor.fetchone()
        if not row: raise Exception("No TLS info avaliable")
        leaf_cert_der: bytes = row[2]
        cursor.close()

        try:
            parsed_leaf: ASN1Result = ASN1Parser.parse_der_cert(leaf_cert_der)
        except Exception:
            raise ParseError

        # 4. hostname mismatch
        if host not in parsed_leaf.subject_cn_list:
            wildcard_host = ".".join(["*"] + host.split(".")[1:])
            if wildcard_host not in parsed_leaf.subject_cn_list:
                error_code.add("hostname_mismatch")

        # 5. check expired certs
        date_obj = datetime.strptime(parsed_leaf.not_after, "%Y-%m-%d-%H-%M-%S")
        if date_obj < scan_time:
            error_code.add("expired_certs")

        # 6. self-signed certs
        if parsed_leaf.self_signed:
            error_code.add("self_signed_certs")

        # 7. check for cert trust
        trust_conn = engine_cert.raw_connection()
        with trust_conn.cursor() as cursor:
            query = """
                SELECT * FROM cert_trust
                WHERE sha256 = %s
            """
            cursor.execute(query, (leaf_sha256,))
            row = cursor.fetchone()

            if row:
                if int(row[-1]) != 0:
                    error_code.add("invalid_cert")
            else:
                error_code.add("invalid_cert")
                # TODO: use the chain to verify in time
                # placeholders = ','.join(['%s'] * len(chain_sha256_list))
                # if placeholders:
                #     query = f"""
                #         SELECT * FROM cert
                #         WHERE sha256 IN ({placeholders})
                #     """
                #     cursor.execute(query, chain_sha256_list)
                #     all_rows = cursor.fetchall()

                #     # 用 dict 映射 cert_hash 到结果
                #     hash_to_row = {r[1]: r[2] for r in all_rows}  # 假设 cert_hash 是第一列

    except ParseError as e:
        primary_logger.error(e)
        error_code.add("cert_broke")

    except Exception as e:
        primary_logger.error(e)
        pass

    finally:
        return {
            "flag" : AnalyzeConfig.TASK_WEB_SECURITY,
            "domain" : domain,
            "ip" : ip,
            "tls_version" : tls_version,
            "tls_cipher" : tls_cipher,
            "cert_hash_list" : chain_sha256_list,
            "error_code" : list(error_code)
        }
