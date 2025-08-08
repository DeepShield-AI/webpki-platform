
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert
from backend.logger.logger import primary_logger
from backend.parser.asn1_parser import ASN1Parser, ASN1Result

@celery_app.task
def build_all_from_table(start_id=0) -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "ca_cert", start_id=start_id):
        ca_info_from_row.delay(row)
    return True

@celery_app.task
def ca_info_from_row(row: list) -> str:
    enqueue_result(_ca_info(row[2]))
    return True

def _ca_info(cert_der: bytes) -> str:
    try:
        parsed: ASN1Result = ASN1Parser.parse_der_cert(cert_der)

        #   `subject` JSON,
        #   `spki` JSON,
        #   `certs` JSON,
        #   `issued_certs` INT,
        #   `parent` JSON,
        #   `child` JSON

        cert_conn = engine_cert.raw_connection()
        with cert_conn.cursor() as cursor:
            query = """
                SELECT id from cert
                WHERE sha256 = %s
            """
            cursor.execute(query, (parsed.sha256,))
            row = cursor.fetchone()

        return {
            "flag" : AnalyzeConfig.TASK_CA_PROFILE,
            "ca_sha256" : parsed.ca_id_sha256,
            "subject" : parsed.subject,
            "spki" : parsed.spki,
            "ski" : parsed.ski
        }

    except Exception as e:
        primary_logger.error(e)
        return {
            "flag" : AnalyzeConfig.TASK_CA_PROFILE,
            "error" : str(e)
        }
