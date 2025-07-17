
import requests
from datetime import datetime, timedelta, timezone
from readerwriterlock import rwlock
from requests.exceptions import RequestException
from typing import Dict, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import (
    Certificate,
    ReasonFlags,
    CRLReason,
    CertificateRevocationList,
    load_pem_x509_certificate,
    load_der_x509_certificate,
    load_pem_x509_crl,
    load_der_x509_crl
)
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseStatus,
    OCSPCertStatus,
    OCSPResponse,
    load_der_ocsp_response
)

from backend.analyzer.utils import enqueue_result, stream_by_id
from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import ASN1Parser

# Cache for CRL results
CRL_CACHE_TIMEOUT = timedelta(hours=1)
crl_cache: Dict[str, Tuple[datetime, CertificateRevocationList]] = {}
lock = rwlock.RWLockFair()

def get_crl_from_cache(key: str):
    with lock.gen_rlock():
        value = crl_cache.get(key)
        if value:
            if datetime.now(timezone.utc) - value[0] < CRL_CACHE_TIMEOUT:
                return value
            else:
                # 过期
                return None
        return None

def set_crl_to_cache(key: str, crl: CertificateRevocationList):
    with lock.gen_wlock():
        crl_cache[key] = (datetime.now(timezone.utc), crl)

REASONFLAG_MAPPING = {
    None : 0,
    ReasonFlags.key_compromise: 1,
    ReasonFlags.ca_compromise: 2,
    ReasonFlags.affiliation_changed: 3,
    ReasonFlags.superseded: 4,
    ReasonFlags.cessation_of_operation: 5,
    ReasonFlags.certificate_hold: 6,
    ReasonFlags.privilege_withdrawn: 7,
    ReasonFlags.aa_compromise: 8,
}

OCSP_STATUS_MAPPING = {
    OCSPCertStatus.UNKNOWN : 0,
    OCSPCertStatus.GOOD : 1,
    OCSPCertStatus.REVOKED : 2,
    OCSPResponseStatus.UNAUTHORIZED : 3
}

TYPE_CRL = 0
TYPE_OCSP = 1

CRL_UNKNOWN = 0
CRL_GOOD = 1
CRL_REVOKED = 2

@celery_app.task
def cleanup_crl_cache():
    """可定时运行清理任务"""
    with lock.gen_wlock():
        now = datetime.now(timezone.utc)
        expired_keys = [k for k, (ts, _) in crl_cache.items() if now - ts > CRL_CACHE_TIMEOUT]
        for k in expired_keys:
            del crl_cache[k]


@celery_app.task
def build_all_from_table(output_dir: str) -> str:
    for row in stream_by_id(engine_cert.raw_connection(), "cert"):
        analyze_cert_revocation_from_row.delay(row, output_dir)
    return True


@celery_app.task
def analyze_cert_revocation_from_row(row: list, output_dir: str) -> str:
    _analyze_cert_revocation(row[0], row[2])


def _analyze_cert_revocation(id: int, cert_der: bytes) -> str:
    try:
        parsed: dict = ASN1Parser.parse_native_pretty_der(cert_der)
        extensions = parsed['tbs_certificate']["extensions"]
        def find_ext(name):
            if extensions:
                for e in extensions:
                    if e["extn_id"] == name:
                        return e
            return None

    except Exception as e:
        primary_logger.error(e)
        return

    try:
        # CRL
        crl_ext = find_ext("crl_distribution_points")
        if crl_ext:
            values = crl_ext["extn_value"]
            for value in values:
                distribution_points = value["distribution_point"]

                for distribution_point in distribution_points:
                    primary_logger.info(distribution_point)
                    enqueue_result({
                        "flag" : AnalyzeConfig.TASK_CERT_REVOKE,
                        "id" : id,
                        "type" : TYPE_CRL,
                        "result" : get_revocation_status_from_crl(distribution_point, cert_der)
                    })
    except Exception as e:
        primary_logger.error(e)
        pass

    try:
        # OCSP
        aia_ext = find_ext("authority_information_access")
        if aia_ext:
            values = aia_ext["extn_value"]
            for value in values:
                if value.get("access_method", None) == "ca_issuers":
                    issuer_location = value.get("access_location", None)
                    ca_issuer = get_issuer(issuer_location)
                    if ca_issuer:
                        for value in values:
                            if value.get("access_method", None) == "ocsp":
                                access_location = value.get("access_location", None)
                                if access_location: enqueue_result({
                                                        "flag" : AnalyzeConfig.TASK_CERT_REVOKE,
                                                        "id" : id,
                                                        "type" : TYPE_OCSP,
                                                        "result" : get_revocation_status_from_ocsp(access_location, cert_der, ca_issuer)
                                                    })
    except Exception as e:
        primary_logger.error(e)
        pass


# return dict to enqueue
def get_revocation_status_from_crl(
        crl_distribution_point : str, 
        cert_der : bytes,
        use_proxy=False
    ) -> dict:

    '''
        Warning: return False does not always mean the cert is not revoked
        
        Sometimes, the CA might remove the cert from CRL after a period of time of expiration to reduce the CRL size
        So make sure to check whether the cert is expired in the caller
    '''
    parsed: dict = ASN1Parser.parse_native_pretty_der(cert_der)
    serial_number : int = parsed['tbs_certificate']['serial_number']
    request_time, crl = request_crl(crl_distribution_point, use_proxy=use_proxy)

    if crl:
        crl_entry = crl.get_revoked_certificate_by_serial_number(serial_number)
        primary_logger.info(crl_entry)
        if crl_entry:
            # revoked
            status = CRL_REVOKED
            revoke_time = crl_entry.revocation_date_utc
            reason_flag = crl_entry.extensions.get_extension_for_class(CRLReason).value.reason
        else:
            # not revoked
            status = CRL_GOOD
            revoke_time = None
            reason_flag = None
    else:
        # No CRL response - Unkown
        status = CRL_UNKNOWN
        revoke_time = None
        reason_flag = None

    return {        
        "dist_point" : crl_distribution_point,
        "request_time" : request_time,
        "status" : status,
        "revoke_time" : revoke_time,
        "reason_flag" : reason_flag
    }


def request_crl(
        crl_distribution_point : str,
        retry_times : int = 2,
        use_proxy : bool = False
    ) -> Tuple[datetime, CertificateRevocationList]:

    if retry_times <= 0:
        primary_logger.error(f"Can not retrieve CRL after retrying several times...")
        return (datetime.now(timezone.utc), None)

    # Check cache hit
    cache_result = get_crl_from_cache(crl_distribution_point)
    if cache_result is not None:
        primary_logger.debug(cache_result)
        return cache_result
    
    try:
        # primary_logger.debug(f"Requesting CRL from {crl_distribution_point}...")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
        }
        request_time = datetime.now(timezone.utc)
        if use_proxy:
            crl_response : requests.Response = requests.get(crl_distribution_point, headers=headers, timeout=10, proxies="127.0.0.1:33210")
        else:
            crl_response : requests.Response = requests.get(crl_distribution_point, headers=headers, timeout=10)

        if not crl_response.status_code == 200:
            primary_logger.warning(f"Server {crl_distribution_point} rejected CRL reqeust")
            return (request_time, None)

        crl = load_der_x509_crl(crl_response.content, default_backend())
        set_crl_to_cache(crl_distribution_point, crl)
        return (request_time, crl)

    except requests.exceptions.RequestException:
        return request_crl(crl_distribution_point, retry_times - 1)
    except ValueError:
        try:
            crl = load_pem_x509_crl(crl_response.content, default_backend())
            primary_logger.warning("CRL response is encoded with PEM")
            set_crl_to_cache(crl_distribution_point, crl)
            return (request_time, crl)
        except:
            return (request_time, None)


def get_issuer(issuer_location : str, use_proxy = False) -> Certificate:

    if not issuer_location: return None

    for _ in range(2):  # 限制最大重试次数
        try:
            if use_proxy:
                raw_response : requests.Response = requests.get(issuer_location, timeout=2, proxies="127.0.0.1:33210")
            else:
                raw_response : requests.Response = requests.get(issuer_location, timeout=2)
            raw_response.raise_for_status()
            
            # 检查是否成功获取了证书内容
            if b'-----BEGIN CERTIFICATE-----' in raw_response.content:
                start_index = raw_response.content.find(b'-----BEGIN CERTIFICATE-----')
                certificate_content = raw_response.content[start_index:]
                issuer = load_pem_x509_certificate(certificate_content)
            else:
                issuer = load_der_x509_certificate(raw_response.content)

            if issuer: return issuer
        except RequestException as e:
            # my_logger.warn(f"Request failed: {e}")
            continue
        except Exception as e:
            primary_logger.error(f"An unexpected error occurred: {e}")

    return None
        

def get_revocation_status_from_ocsp(
        access_location : str,
        cert_der : bytes,
        issuer_cert : Certificate,
        use_proxy=False
    )-> dict:

    cert = load_der_x509_certificate(cert_der)
    request_time, ocsp = request_ocsp(cert, issuer_cert, access_location, use_proxy=use_proxy)

    if not ocsp:
        # No response
        status = OCSP_STATUS_MAPPING[OCSPCertStatus.UNKNOWN]
        revoke_time = None
        reason_flag = None
    else:
        ocsp_status : OCSPResponseStatus = ocsp.response_status
        if ocsp_status == OCSPResponseStatus.UNAUTHORIZED:
            status = OCSP_STATUS_MAPPING[OCSPResponseStatus.UNAUTHORIZED]
            revoke_time = None
            reason_flag = None
        elif ocsp_status == OCSPResponseStatus.SUCCESSFUL:
            status = OCSP_STATUS_MAPPING[ocsp.certificate_status]
            if status == OCSPCertStatus.REVOKED:
                revoke_time = ocsp.revocation_time
                reason_flag = REASONFLAG_MAPPING[ocsp.revocation_reason]
            else:
                revoke_time = None
                reason_flag = None
        else:
            status = OCSP_STATUS_MAPPING[OCSPCertStatus.UNKNOWN]
            revoke_time = None
            reason_flag = None

    return {
        "dist_point" : access_location,
        "request_time" : request_time,
        "status" : status,
        "revoke_time" : revoke_time,
        "reason_flag" : reason_flag
    }    

'''
    Create OCSP request:
        Contact OCSP server and check the cert OCSP status

    OCSP Request Data Structure Example:
        Version: 1 (0x0)
        Requestor List:
            Certificate ID:
            Hash Algorithm: sha1
            Issuer Name Hash: 52FECA108DB4E5AB5268930D27C82FF215E24BB5
            Issuer Key Hash: 00AB91FC216226979AA8791B61419060A96267FD
            Serial Number: 3300AB78D29C2E8D26F9DF8169000000AB78D2
        Request Extensions:
            OCSP Nonce: 
                0410CE52A9CC9405C6B438E23DB7607410A9
'''
def request_ocsp(
        cert : Certificate,
        issuer : Certificate,
        access_location : str,
        hash : hashes = SHA256(),
        retry_times : int = 2,
        use_proxy : bool = False
    ) -> Tuple[datetime, OCSPResponse]:

    if retry_times <= 0:
        # my_logger.error(f"OCSP server {server_url} does not respond after retrying several times...")
        return (datetime.now(timezone.utc), None)

    '''
        From doc:
        While RFC 5019 originally required SHA1,
        RFC 6960 updates that to SHA256.
        However, depending on your requirements you may need to use SHA1
        for compatibility reasons.

        So we do the following:
        Use SHA1 first, if return status is OCSPResponseStatus.UNAUTHORIZED,
        we switch to SHA256 next

        Update on 24/05/21:
        Skip SHA1, use SHA256 directly to save time
    '''
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hash)
    request = builder.build()

    try:
        try:
            # primary_logger.debug(f"Requesting OCSP response from {access_location}...")
            request_time = datetime.now(timezone.utc)
            if use_proxy:
                raw_response = requests.post(
                    access_location,
                    data=request.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"},
                    timeout=2,
                    proxies="127.0.0.1:33210"
                )
            else:
                raw_response = requests.post(
                    access_location,
                    data=request.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"},
                    timeout=2
                )
            if not raw_response.status_code == 200:
                primary_logger.warning(f"Server {access_location} rejected OCSP reqeust")
                return (request_time, None)

        except requests.exceptions.RequestException as e:
            return request_ocsp(cert, issuer, access_location, hash, retry_times - 1)

        response = load_der_ocsp_response(raw_response.content)
        return (request_time, response)

    # Sometimes, the response may not complete...
    except ValueError as e:
        # my_logger.warn(f"OCSP response from {server_url} is not complete, retrying...")
        return request_ocsp(cert, issuer, access_location, hash, retry_times - 1)
    except Exception as e:
        primary_logger.error(f"Error when getting OCSP response: {e}")
        return (request_time, None)
