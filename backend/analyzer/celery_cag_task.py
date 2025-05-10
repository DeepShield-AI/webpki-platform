
import json
import redis
import hashlib
import base64
from datetime import datetime
from collections import OrderedDict

from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser
from backend.utils.exception import *
from backend.utils.type import sort_dict_by_key, sort_list_by_key
from backend.utils.cert import get_cert_sha256_hex_from_str

r = redis.Redis()
r.expire("analyze_results_queue", 1 * 24 * 3600)  # 1 天过期

# Redis 只能存储字符串或字节
def enqueue_result(result: dict):
    r.rpush("analyze_results_queue", json.dumps(result))

# go through the tls_handshake table
def stream_by_id(table_name, batch_size=1000, start_id=0):

    conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    last_id = start_id
    while True:
        if last_id:
            query = f"""
                SELECT * FROM {table_name}
                WHERE id > %s
                ORDER BY id ASC
                LIMIT %s
            """
            cursor.execute(query, (last_id, batch_size))
        else:
            query = f"""
                SELECT * FROM {table_name}
                ORDER BY id ASC
                LIMIT %s
            """
            cursor.execute(query, (batch_size,))
        rows = cursor.fetchall()
        if not rows:
            break
        yield from rows # this asyc make sure the read does not cause too much memory
        last_id = rows[-1][0]
    cursor.close()

# go through the cert table
def stream_by_cert_hash(table_name, batch_size=1000, start_hash=""):

    conn = engine_cert.raw_connection()
    cursor = conn.cursor()
    last_hash = start_hash
    while True:
        if last_hash:
            query = f"""
                SELECT * FROM {table_name}
                WHERE cert_hash > %s
                ORDER BY cert_hash ASC
                LIMIT %s
            """
            cursor.execute(query, (last_hash, batch_size))
        else:
            query = f"""
                SELECT * FROM {table_name}
                ORDER BY cert_hash ASC
                LIMIT %s
            """
            cursor.execute(query, (batch_size,))
        rows = cursor.fetchall()
        if not rows:
            break
        yield from rows # this asyc make sure the read does not cause too much memory
        last_hash = rows[-1][0]  # 假设 cert_hash 是第一列
    cursor.close()

@celery_app.task
def build_all(output_dir: str) -> str:

    # 目前 CAG 由两个部分组成
    # 1. 证书中的内容（包括 密钥 和 CA）
    # 2. TLS 扫描中的内容
    for row in stream_by_cert_hash("cert"):
        cag_cert.delay(row, output_dir)
    for row in stream_by_id("tlshandshake"):
        cag_tls.delay(row, output_dir)

    return True

@celery_app.task
def cag_cert(row: list, output_dir: str) -> str:
    try:
        parsed_cert = PEMParser.parse_native(row[1])
    except:
        # only add cert node if the cert structure is broken
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "node",
            "id" : f"Cert_{cert_hash}",
            "name" : cert_hash[0:10],
            "type" : "Cert"
        })
        return True

    cert_hash = row[0]
    public_key_hash = get_cert_sha256_hex_from_str(str(parsed_cert['tbs_certificate']['subject_public_key_info']))
    ca_org = parsed_cert['tbs_certificate']['issuer'].get('organization_name', None)
    if ca_org: ca_org_hash = get_cert_sha256_hex_from_str(str(ca_org))
    sub_org = parsed_cert['tbs_certificate']['subject'].get('organization_name', None)
    if sub_org: sub_org_hash = get_cert_sha256_hex_from_str(str(sub_org))

    # first, add cert, public key, subject org and issuer org nodes
    enqueue_result({
        "flag" : AnalyzeConfig.TASK_CAG,
        "out_dir" : output_dir,
        "cag_type" : "node",
        "id" : f"Cert_{cert_hash}",
        "name" : cert_hash[0:10],
        "type" : "Cert"
    })

    enqueue_result({
        "flag" : AnalyzeConfig.TASK_CAG,
        "out_dir" : output_dir,
        "cag_type" : "node",
        "id" : f"Pubkey_{public_key_hash}",
        "name" : public_key_hash[0:10],
        "type" : "Pubkey"
    })

    if ca_org:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "node",
            "id" : f"Org_{ca_org_hash}",
            "name" : ca_org,
            "type" : "Org"
        })

    if sub_org:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "node",
            "id" : f"Org_{sub_org_hash}",
            "name" : sub_org,
            "type" : "Org"
        })

    # second, add link from cert to public key
    enqueue_result({
        "flag" : AnalyzeConfig.TASK_CAG,
        "out_dir" : output_dir,
        "cag_type" : "edge",
        "relation" : "e_pub_key",
        "source" : f"Cert_{cert_hash}",
        "target" : f"Pubkey_{public_key_hash}"
    })
    
    # third, add link from subject org to cert
    if sub_org:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "edge",
            "relation" : "e_sub_org",
            "source" : f"Org_{sub_org_hash}",
            "target" : f"Cert_{cert_hash}"
        })

    # final, add link from issuer org to cert
    if ca_org:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "edge",
            "relation" : "e_ca_org",
            "source" : f"Org_{ca_org_hash}",
            "target" : f"Cert_{cert_hash}"
        })

    return True

@celery_app.task
def cag_tls(row: list, output_dir: str) -> str:

    domain = row[1]
    # domain could be none
    if domain: domain_hash = get_cert_sha256_hex_from_str(domain)
    ip = row[2]
    ip_hash = get_cert_sha256_hex_from_str(ip)
    cert_hash_list = json.loads(row[-2])
    if cert_hash_list: leaf_cert_hash = cert_hash_list[0]

    # first, add domain, ip nodes
    if domain:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "node",
            "id" : f"Domain_{domain_hash}",
            "name" : domain,
            "type" : "Domain"
        })

    enqueue_result({
        "flag" : AnalyzeConfig.TASK_CAG,
        "out_dir" : output_dir,
        "cag_type" : "node",
        "id" : f"IP_{ip_hash}",
        "name" : ip,
        "type" : "IP"
    })
    
    # second, add domain to IP dns link
    if domain:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "edge",
            "relation" : "e_dns",
            "source" : f"Domain_{domain_hash}",
            "target" : f"IP_{ip_hash}"
        })

    # then, add link from domain to cert
    if cert_hash_list:
        if domain:
            enqueue_result({
                "flag" : AnalyzeConfig.TASK_CAG,
                "out_dir" : output_dir,
                "cag_type" : "edge",
                "relation" : "e_cert",
                "source" : f"Domain_{domain_hash}",
                "target" : f"Cert_{leaf_cert_hash}"
            })
        else:
            # link to ip directly
            enqueue_result({
                "flag" : AnalyzeConfig.TASK_CAG,
                "out_dir" : output_dir,
                "cag_type" : "edge",
                "relation" : "e_cert",
                "source" : f"IP_{ip_hash}",
                "target" : f"Cert_{leaf_cert_hash}"
            })

    return True
