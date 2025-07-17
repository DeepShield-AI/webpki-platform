
from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import ASN1Parser, PEMResult


@celery_app.task
def build_all_from_table() -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "cert"):
        cert_parse_from_row.delay(row)
    return True


@celery_app.task
def cert_parse_from_row(row: list) -> str:
    parse_result = _cert_parse(row[2])
    parse_result["id"] = row[0]
    enqueue_result(parse_result)
    return True


def _cert_parse(cert_der: bytes) -> str:

    try:
        parsed: PEMResult = ASN1Parser.parse_der_cert(cert_der)

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
            "not_valid_before" : parsed.not_before,
            "not_valid_after" : parsed.not_after,
        }

    except Exception as e:
        primary_logger.error(e)
        return {
            "flag" : AnalyzeConfig.TASK_CERT_PARSE,
            "error" : str(e)
        }
