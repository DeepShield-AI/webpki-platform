
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import ASN1Parser, PEMResult

@celery_app.task
def build_all_from_table() -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "ca_cert"):
        ca_info_from_row.delay(row)
    return True

@celery_app.task
def ca_info_from_row(row: list) -> str:
    enqueue_result(_ca_info(row[2]))
    return True

def _ca_info(cert_der: bytes) -> str:
    try:
        parsed: PEMResult = ASN1Parser.parse_der_cert(cert_der)

        #   `subject` JSON,
        #   `spki` JSON,
        #   `certs` JSON,
        #   `issued_certs` INT,
        #   `parent` JSON,
        #   `child` JSON

        return {
            "flag" : AnalyzeConfig.TASK_CA_PROFILE,
            "ca_sha256" : parsed.ca_id_sha256,
            "subject" : parsed.subject,
            "spki" : parsed.spki,
            "cert_sha256" : parsed.sha256
        }

    except Exception as e:
        primary_logger.error(e)
        return {
            "flag" : AnalyzeConfig.TASK_CA_PROFILE,
            "error" : str(e)
        }
