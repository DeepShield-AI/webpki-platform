
import base64
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_tls, engine_cert, engine_ca
from backend.utils.domain import check_input_type
from backend.utils.network import resolve_host_dns
from backend.logger.logger import primary_logger
from backend.parser.asn1_parser import ASN1Parser, ASN1Result

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

# #########
# Depreacted
# #########
@celery_app.task
def build_all_from_table(output_dir: str) -> str:

    # 目前 CAG 由两个部分组成
    # 1. 证书中的内容（包括 密钥 和 CA）
    # 2. TLS 扫描中的内容
    for row in stream_by_id(engine_cert.raw_connection(), "cert"):
        cag_cert_from_row.delay(row, output_dir)
    for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake"):
        cag_tls_from_row.delay(row, output_dir)
    return True

@celery_app.task
def cag_cert_from_row(row: list, output_dir: str):
    cag_add_cert_parse(row[1], row[2], output_dir)
    return True

@celery_app.task
def cag_tls_from_row(row: list, output_dir: str) -> str:
    cag_add_dns(row[1], row[2], json.loads(row[-2]), output_dir)
    return True

# #########
# Depreacted
# #########



def cag_add_cert_parse(cert_id: int, current_graph_data: dict):

    if not current_graph_data:
        current_graph_data = {
            "nodes": [],
            "links": []
        }

    try:
        conn = engine_cert.raw_connection()
        with conn.cursor() as cursor:
            query = """
                SELECT * from cert_search
                WHERE id = %s
            """
            cursor.execute(query, (cert_id,))
            row = cursor.fetchone()

        conn.close()
        if not row: return current_graph_data

        subject_list = json.loads(row[3])
        subject = json.loads(row[4])
        issuer = json.loads(row[5])
        spkisha256 = row[6]

        print(subject, issuer)

        # use subject_cn as the cert node name
        cert_name = subject.get('common_name', None)

        # link subject list
        for s in subject_list:
            # check if the subject is domain like 
            if check_input_type(s) == "Domain":
                current_graph_data = cag_add_dns(s, current_graph_data)

                current_graph_data["links"].append({
                    "type" : "e_cert_domain",
                    "source" : cert_id,
                    "target" : s
                })
            elif check_input_type(s) == "IP Address":
                current_graph_data["nodes"].append({
                    "id" : s,
                    "name" : s,
                    "type" : "ip"
                })

                current_graph_data["links"].append({
                    "type" : "e_cert_ip",
                    "source" : cert_id,
                    "target" : s
                })

        # link subject org
        sub_org = subject.get('organization_name', None)
        if sub_org:
            current_graph_data["nodes"].append({
                "id" : sub_org,
                "name" : sub_org,
                "type" : "org"
            })
            current_graph_data["links"].append({
                "type" : "e_sub_org",
                "source" : sub_org,
                "target" : cert_id
            })

        # link issuer_org
        issuer_org = issuer.get('organization_name', None)
        if issuer_org:
            current_graph_data["nodes"].append({
                "id" : issuer_org,
                "name" : issuer_org,
                "type" : "issuer"
            })

            current_graph_data["links"].append({
                "type" : "e_ca_org",
                "source" : issuer_org,
                "target" : cert_id
            })

        # link public key
        current_graph_data["nodes"].append({
            "id" : spkisha256,
            "name" : f"pub_key: {spkisha256}",
            "type" : "pubkey"
        })

        current_graph_data["links"].append({
            "type" : "e_pub_key",
            "source" : cert_id,
            "target" : spkisha256
        })
        
    except Exception as e:
        primary_logger.error(e)
        cert_name = row[1]     # sha256
    finally:
        # add this root cert node
        current_graph_data["nodes"].append({
            "id": cert_id,
            "name": cert_name,
            "type": "cert",
            "root": True
        })
        return current_graph_data


def cag_add_dns(domain: str, current_graph_data):

    if not current_graph_data:
        current_graph_data = {
            "nodes": [],
            "links": []
        }

    current_graph_data["nodes"].append({
        "id": domain,
        "name": domain,
        "type": "domain",
    })

    if domain.startswith("*."): return current_graph_data

    v4, v6 = resolve_host_dns(domain, lifetime=1, timeout=1)
    for ip in v4 + v6:
        current_graph_data["nodes"].append({
            "id" : ip,
            "name" : ip,
            "type" : "ip"
        })

        current_graph_data["links"].append({
            "type" : "e_domain_ip",
            "source" : domain,
            "target" : ip
        })

    return current_graph_data


def cag_add_cert_chain(cert_id, current_graph_data):

    if not current_graph_data:
        current_graph_data = {
            "nodes": [],
            "links": []
        }

    cert_conn = engine_cert.raw_connection()
    ca_conn = engine_ca.raw_connection()

    with cert_conn.cursor() as cursor:
        query = """
            SELECT * from cert
            WHERE id = %s
        """
        cursor.execute(query, (cert_id,))
        row = cursor.fetchone()

    if not row: return current_graph_data

    cert_der = row[2]
    parsed : ASN1Result = ASN1Parser.parse_der_cert(cert_der)
    current_issuer_cn = parsed.issuer["common_name"]
    if parsed.subject == parsed.issuer:
        # loop until reach self-signed root
        return current_graph_data

    parsed_raw = ASN1Parser.parse_der_raw(cert_der)
    tbs_bytes = parsed_raw['tbs_certificate'].dump()
    signature_bytes = parsed_raw['signature_value'].native
    signature_algo = parsed.signature_algo

    try:
        hash_algo = get_hash_algorithm(signature_algo)
    except Exception as e:
        primary_logger.error(e)
        return current_graph_data

    # 1. issuer = subject
    # search from ca_certs to find the matched issuer
    with ca_conn.cursor() as cursor:
        query = """
            SELECT * from ca
            WHERE JSON_CONTAINS(subject, CAST(%s AS JSON))
            AND JSON_CONTAINS(CAST(%s AS JSON), subject)
        """
        cursor.execute(query, (json.dumps(parsed.issuer), json.dumps(parsed.issuer)))
        rows = cursor.fetchall()

        if not rows:
            primary_logger.warning(f"No ca {parsed.issuer} found in database, please check reason")
            return current_graph_data

    for row in rows:
        # 2. check ski and aki (if have)
        issuer_ski = row[4]
        if issuer_ski and parsed.aki:
            if issuer_ski != parsed.aki:
                continue

        # 3. check signature
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
                print(signature_bytes)
                print(tbs_bytes)
                print(hash_algo)
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

        except InvalidSignature:
            primary_logger.warning("签名无效，证书未被该 CA 签发")
            continue
        except UnsupportedAlgorithm as e:
            primary_logger.error(f"不支持的算法: {e}")
            continue
        except Exception as e:
            primary_logger.error(f"签名验证失败: {e}")
            continue

        # 4. not_before time check
        # TODO:
        # 

        # if all passed, add nodes and links
        ca_cert_id_list = json.loads(row[5])

        for ca_cert_id in ca_cert_id_list:
            current_graph_data["nodes"].append({
                "id" : ca_cert_id,
                "name" : current_issuer_cn,
                "type" : "cert"
            })

            current_graph_data["links"].append({
                "type" : "e_cert_chain",
                "source" : cert_id,
                "target" : ca_cert_id
            })

            with cert_conn.cursor() as cursor:
                query = """
                    SELECT * from cert
                    WHERE sha256 = %s
                """
                cursor.execute(query, (cert_id,))
                row = cursor.fetchone()

            current_graph_data = cag_add_cert_chain(ca_cert_id, current_graph_data)

    cert_conn.close()
    ca_conn.close()
    return current_graph_data


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
