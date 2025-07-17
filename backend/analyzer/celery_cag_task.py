
import json
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_tls, engine_cert
from backend.config.analyze_config import AnalyzeConfig
from backend.parser.pem_parser import ASN1Parser
from backend.utils.cert import get_sha256_hex_from_str, get_sha256_hex_from_bytes

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
    _cag_cert(row[1], row[2], output_dir)
    return True


def _cag_cert(sha256: str, cert_der: bytes, output_dir: str):

    try:
        parsed_cert = ASN1Parser.parse_der(cert_der)
    except:
        # only add cert node if the cert structure is broken
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "node",
            "id" : f"Cert_{sha256}",
            "name" : sha256[0:10],
            "type" : "Cert"
        })
        return True

    public_key_hash = get_sha256_hex_from_bytes(parsed_cert['tbs_certificate']['subject_public_key_info'].dump())
    ca_org = parsed_cert['tbs_certificate']['issuer'].native.get('organization_name', None)
    if ca_org: ca_org_hash = get_sha256_hex_from_str(str(ca_org))
    sub_org = parsed_cert['tbs_certificate']['subject'].native.get('organization_name', None)
    if sub_org: sub_org_hash = get_sha256_hex_from_str(str(sub_org))

    # first, add cert, public key, subject org and issuer org nodes
    enqueue_result({
        "flag" : AnalyzeConfig.TASK_CAG,
        "out_dir" : output_dir,
        "cag_type" : "node",
        "id" : f"Cert_{sha256}",
        "name" : sha256[0:10],
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
        "source" : f"Cert_{sha256}",
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
            "target" : f"Cert_{sha256}"
        })

    # final, add link from issuer org to cert
    if ca_org:
        enqueue_result({
            "flag" : AnalyzeConfig.TASK_CAG,
            "out_dir" : output_dir,
            "cag_type" : "edge",
            "relation" : "e_ca_org",
            "source" : f"Org_{ca_org_hash}",
            "target" : f"Cert_{sha256}"
        })

    return True


@celery_app.task
def cag_tls_from_row(row: list, output_dir: str) -> str:
    _cag_tls(row[1], row[2], json.loads(row[-2]), output_dir)
    return True


def _cag_tls(
        domain: str,
        ip: str,
        cert_sha256_list: list,
        output_dir: str
    ):

    if domain: domain_hash = get_sha256_hex_from_str(domain)
    ip_hash = get_sha256_hex_from_str(ip)
    if cert_sha256_list: leaf_cert_hash = cert_sha256_list[0]

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
    if cert_sha256_list:
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
