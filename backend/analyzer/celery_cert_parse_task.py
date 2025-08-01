
import json
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_ca
from backend.logger.logger import primary_logger
from backend.parser.asn1_parser import ASN1Parser, ASN1Result
from backend.utils.cert import get_sha256_hex_from_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

@celery_app.task
def build_all_from_table() -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "cert"):
        cert_parse_from_row.delay(row)
    return True


@celery_app.task
def cert_parse_from_row(row: list) -> str:
    parse_result = _cert_parse(row[2])
    trusted = check_cert_trusted(row[2])
    parse_result["id"] = row[0]
    parse_result["trusted"] = trusted
    enqueue_result(parse_result)
    return True


def _cert_parse(cert_der: bytes) -> str:

    try:
        parsed: ASN1Result = ASN1Parser.parse_der_cert(cert_der)

        # `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
        # `serial` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
        # `subject_cn_list` JSON,
        # `subject` JSON,
        # `issuer` JSON,
        # `spkisha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        # `ski` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
        return {
            "flag" : AnalyzeConfig.TASK_CERT_PARSE,
            "sha256" : parsed.sha256,
            "serial" : parsed.serial,
            "subject_cn_list" : parsed.subject_cn_list,
            "subject" : parsed.subject,
            "issuer" : parsed.issuer,
            "spkisha256" : parsed.spkisha256,
            "ski" : parsed.ski,
            "aki" : parsed.aki,
            "not_valid_before" : parsed.not_before,
            "not_valid_after" : parsed.not_after,
            "type" : parsed.cert_type
        }

    except Exception as e:
        primary_logger.error(e)
        return {
            "flag" : AnalyzeConfig.TASK_CERT_PARSE,
            "error" : str(e)
        }


def check_cert_trusted(cert_der : bytes) -> bool:

    roots = find_all_possible_roots(cert_der)
    ca_conn = engine_ca.raw_connection()

    for root in roots:
        with ca_conn.cursor() as cursor:
            query = """
                SELECT * from mozilla_root
                WHERE sha256 = %s
            """
            cursor.execute(query, (get_sha256_hex_from_bytes(root),))
            row = cursor.fetchone()
            if row:
                ca_conn.close()
                return True

    ca_conn.close()
    return False


def find_all_possible_roots(cert_der) -> list:

    ca_conn = engine_ca.raw_connection()
    visited = set()
    result_roots = []

    # 用于 DFS 的栈
    stack = [cert_der]

    while stack:
        try:
            current_cert_der = stack.pop()
        except IndexError:
            break

        parsed = ASN1Parser.parse_der_cert(current_cert_der)
        parsed_raw = ASN1Parser.parse_der_raw(current_cert_der)
        tbs_bytes = parsed_raw['tbs_certificate'].dump()
        signature_bytes = parsed_raw['signature_value'].native
        signature_algo = parsed.signature_algo

        if parsed.sha256 in visited:
            continue
        visited.add(parsed.sha256)

        try:
            hash_algo = get_hash_algorithm(signature_algo)
        except Exception as e:
            primary_logger.error(f"解析签名算法失败: {e}")
            continue

        # 是自签发的，添加为根
        if parsed.subject == parsed.issuer:
            result_roots.append(current_cert_der)
            continue

        # 查询可能的 issuer
        with ca_conn.cursor() as cursor:
            query = """
                SELECT * FROM ca
                WHERE JSON_CONTAINS(subject, CAST(%s AS JSON))
                AND JSON_CONTAINS(CAST(%s AS JSON), subject)
            """
            cursor.execute(query, (json.dumps(parsed.issuer), json.dumps(parsed.issuer)))
            rows = cursor.fetchall()

        if not rows:
            primary_logger.warning(f"未在数据库中找到 issuer: {parsed.issuer}")
            continue

        for row in rows:
            issuer_spki_der_bytes = row[3]
            issuer_ski = row[4]
            issuer_cert_der = row[5]  # 假设是 DER 编码的证书

            # 如果有 AKI/SKI 信息，先过滤掉不匹配的
            if issuer_ski and parsed.aki:
                if issuer_ski != parsed.aki:
                    continue

            issuer_spki_der_bytes = row[3]
            issuer_public_key = serialization.load_der_public_key(
                issuer_spki_der_bytes,
                backend=default_backend()
            )

            try:
                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        signature_bytes,
                        tbs_bytes,
                        padding.PKCS1v15(),
                        hash_algo
                    )

                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        signature_bytes,
                        tbs_bytes,
                        ec.ECDSA(hash_algo)
                    )

                elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
                    issuer_public_key.verify(
                        signature_bytes,
                        tbs_bytes
                    )

                elif isinstance(issuer_public_key, dsa.DSAPublicKey):
                    issuer_public_key.verify(
                        signature_bytes,
                        tbs_bytes,
                        hash_algo
                    )

                else:
                    raise ValueError(f"不支持的公钥类型: {type(issuer_public_key)}")

                # 签名验证通过，加入栈中，继续向上找
                stack.append(issuer_cert_der)

            except InvalidSignature:
                primary_logger.warning("签名无效，证书未被该 CA 签发")
                continue
            except UnsupportedAlgorithm as e:
                primary_logger.error(f"不支持的算法: {e}")
                continue
            except Exception as e:
                primary_logger.error(f"签名验证失败: {e}")
                continue

    ca_conn.close()
    return result_roots


def get_hash_algorithm(signature_algo: str):
    algo = signature_algo.lower()

    if "sha256" in algo:
        return hashes.SHA256()
    elif "sha384" in algo:
        return hashes.SHA384()
    elif "sha512" in algo:
        return hashes.SHA512()
    elif "sha1" in algo:
        return hashes.SHA1()  # 不推荐，已过时但仍有老证书使用
    elif "md5" in algo:
        return hashes.MD5()   # 非常不安全，仅用于兼容分析
    elif "sha224" in algo:
        return hashes.SHA224()
    else:
        raise ValueError(f"Unsupported or unknown signature algorithm: {signature_algo}")
