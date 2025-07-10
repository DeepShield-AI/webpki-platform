
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.analyzer.utils import enqueue_result, stream_by_id, stream_by_sha256
from backend.celery.celery_db_pool import engine_cert, engine_tls

@celery_app.task
def build_all_from_table() -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "ca_cert"):
        ca_info.delay(row)
    return True

@celery_app.task
def ca_info(row: list) -> str:
    enqueue_result(_ca_info(row))
    return True

def _ca_info(row: list) -> str:

    try:
        cert: bytes = row[2]
        parsed: PEMResult = PEMParser.parse_der_cert(cert)

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
