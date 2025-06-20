
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.analyzer.utils import enqueue_result, stream_by_id, stream_by_cert_hash

@celery_app.task
def build_all_from_table() -> str:
    for row in stream_by_cert_hash("cert"):
        cert_parse.delay(row)
    return True

@celery_app.task
def cert_parse(row: list) -> str:
    enqueue_result(_cert_parse(row))
    return True

def _cert_parse(row: list) -> str:

    try:
        cert: str = row[1]
        parsed: PEMResult = PEMParser.parse_pem_cert(cert)
        return {
            "flag" : AnalyzeConfig.TASK_PARSE,
            "sha256" : row[0],
            "subject_cn_list" : parsed.subject,
            "subject_org" : parsed.subject_org,
            "issuer_cn" : parsed.issuer_cn,
            "issuer_org" : parsed.issuer_org,
            "issuer_country" : parsed.issuer_country,
            "not_valid_before" : parsed.not_before,
            "not_valid_after" : parsed.not_after
        }

    except Exception as e:
        primary_logger.error(e)
        return {
            "flag" : AnalyzeConfig.TASK_PARSE,
            "sha256" : row[0],
            "error" : str(e)
        }
