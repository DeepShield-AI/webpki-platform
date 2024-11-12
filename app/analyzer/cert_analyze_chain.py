


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends.openssl import rsa, ec
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh
from cryptography.hazmat.primitives.asymmetric import types, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import cryptography.hazmat.bindings
from cryptography.x509 import (
    Version,
    Name,
    DNSName,
    Certificate,
    ReasonFlags,
    ExtensionType,
    ObjectIdentifier,
    AttributeNotFound,
    ExtensionNotFound,
    KeyUsage,
    ExtendedKeyUsage,
    CRLDistributionPoints,
    AuthorityInformationAccess,
    BasicConstraints,
    SubjectAlternativeName,
    CertificatePolicies,
    load_pem_x509_certificate,
    load_pem_x509_certificates
)

from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID, ExtendedKeyUsageOID
from cryptography.x509.ocsp import OCSPCertStatus, OCSPResponseStatus, OCSPResponse
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509 import Extensions

from ..utils.cert import (
    domain_extract,
    is_domain_match,
    utc_time_diff_in_days,
    get_name_attribute,
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)

from ..logger.logger import my_logger
from ..utils.type import CertType
from ..utils.exception import ParseError

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Union, Tuple
from queue import Queue
import hashlib
import jsonlines
import json
import os


from sqlalchemy.exc import IntegrityError
from sqlalchemy import Table
from sqlalchemy.dialects.mysql import insert
from ..models import CertAnalysisStats, CertStoreContent, CertStoreRaw, CaCertStore, CertChainRelation, DomainTrustRelation
from ..parser.cert_parser_base import X509ParsedInfo
from app import app, db
from threading import Lock
import threading
import time

from OpenSSL import crypto
import threading
import asyncio
import hashlib
import json
import os

from queue import Queue
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID

from ..parser.pem_parser import PEMParser, PEMResult
from ..utils.domain_lookup import DomainLookup
from ..utils.json import custom_serializer
from ..utils.type import str_to_timestamp
from ..logger.logger import my_logger

class CertScanChainAnalyzer():

    def __init__(
            self,
            scan_id : str,
            scan_input_table : Table,
        ) -> None:

        self.scan_id = scan_id
        self.scan_input_table = scan_input_table
        self.save_scan_chunk_size = 10000
        self.cert_store = crypto.X509Store()


    def analyze_cert_chain(self):
        my_logger.info(f"Starting {self.scan_input_table.name} chain analysis...")
        
        with app.app_context():
            # Prepare root store
            ca_certs = CaCertStore.query.filter()
            ca_certs = [cert.get_raw() for cert in ca_certs]

            for cert in ca_certs:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                self.cert_store.add_cert(root_cert)

            # Analyze
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            while True:
                rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                if not rows:
                    # self.sync_update_info()
                    break

                for row in rows:
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, row[1])
                        issuer = self.get_issuer(cert)
                        self.sync_update_info(cert, issuer)
                    except ValueError:
                        continue

        my_logger.info("Cert chain analysis completed")


    def get_issuer(self, cert):
        try:
            store_ctx = crypto.X509StoreContext(self.cert_store, cert)
            chain = store_ctx.get_verified_chain()
            if len(chain) == 1:
                return chain[0]
            else:
                return chain[1]
        
        except crypto.X509StoreContextError as e:
            # my_logger.error(f"Cert chain analysis failed for cert {get_cert_sha256_hex_from_object(e.certificate.to_cryptography())}...")
            return None


    def sync_update_info(self, cert : crypto.X509, issuer : crypto.X509):
        # with app.app_context():
            if issuer:
                cert_parent_id = get_cert_sha256_hex_from_object(issuer.to_cryptography())
            else:
                cert_parent_id = "Not Found Yet"

            cert_chain_data_to_insert = {
                'CERT_ID' : get_cert_sha256_hex_from_object(cert.to_cryptography()),
                'CERT_PARENT_ID' : cert_parent_id
            }
            insert_cert_store_statement = insert(CertChainRelation).values(cert_chain_data_to_insert).prefix_with('IGNORE')
            db.session.execute(insert_cert_store_statement)
            db.session.commit()


    # do not use now
    def verifySignature(self) -> bool:
        sig_verified = False

        if self.issuer_cert is not None:
            issuer_pub_key = self.issuer_cert.public_key()
            try:
                if issuer_pub_key.__class__ == primitive_rsa.RSAPublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        # Depends on the algorithm used to create the certificate
                        padding.PKCS1v15(),
                        self.cert.signature_hash_algorithm
                    )
                elif issuer_pub_key.__class__ == primitive_ec.EllipticCurvePublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        primitive_ec.ECDSA(hashes.SHA256())
                    )
                else:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes
                    )
                sig_verified = True
            except InvalidSignature:
                my_logger.warn(f"Cert {self.cert.serial_number} signature checking failed")
                sig_verified = False
        else:
            my_logger.warn(f"Cert {self.cert.serial_number} has no issuer cert avaliable")

        return sig_verified


class DomainChainAnalyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/20241110"
        ) -> None:

        self.input_file = input_file
        self.queue = Queue()

        # @Debug only
        self.count = 0
        self.total = 0
        self.lock = Lock()
        self.progress_task = TaskID(-1)
        self.progress = Progress()
        self.console = Console()

        self.saver_thread = threading.Thread(target=self.save_results)
        # saver_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
        self.saver_thread.start()


    def analyze_single(self, json_obj):
        domain = json_obj["domain"]

        try:
            cert = json_obj["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            chain_sha_256 = [get_cert_sha256_hex_from_str(cert["certificate"]["raw"])]
            not_before = datetime.strptime(cert["certificate"]["parsed"]["validity"]["start"], "%Y-%m-%dT%H:%M:%SZ")
            not_after = datetime.strptime(cert["certificate"]["parsed"]["validity"]["end"], "%Y-%m-%dT%H:%M:%SZ")

            chain = cert["chain"]
            chain_sha_256 += [get_cert_sha256_hex_from_str(c["raw"]) for c in chain]

            self.queue.put({
                "domain" : domain,
                "cert_chain" : chain_sha_256,
                "not_before" : not_before,
                "not_after" : not_after
            })

        except Exception as e:
            my_logger.debug(f"Domain {domain} has no cert received")

        self.count += 1
        self.progress.update(self.progress_task, description=f"[green]Completed: {self.count}")
        self.progress.advance(self.progress_task)

    def analyze(self):

        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:

            self.progress_task = self.progress.add_task("[Waiting]")

            if os.path.isfile(self.input_file):
                with open(self.input_file, "r", encoding='utf-8') as file:
                    print(f"Reading file: {self.input_file}")
                    for line in file:
                        json_obj = json.loads(line.strip())
                        self.analyze_single(json_obj)

            # Wait for all elements in queue to be handled
            # self.queue.join()

            # Send the poison pill to stop the saver thread
            self.queue.put(None)
            self.saver_thread.join()


    def save_results(self):
        with app.app_context():
            while True:
                data = self.queue.get()
                if data is None:  # Poison pill to shut down the thread
                    print("Poision detected")
                    break

                trust_relation_data = {
                    "DOMAIN" : data["domain"],
                    "CERT_ID" : data["cert_chain"][0],
                    "NOT_VALID_BEFORE" : data["not_before"],
                    "NOT_VALID_AFTER" : data["not_after"]
                }

                insert_trust_relation_statement = insert(DomainTrustRelation).values([trust_relation_data]).prefix_with('IGNORE')
                db.session.execute(insert_trust_relation_statement)
                db.session.commit()

                chain_length = len(data["cert_chain"])
                chain_data = []
                for i in range(chain_length):
                    try:
                        chain_data.append({
                            "CERT_ID" : data["cert_chain"][i],
                            "CERT_PARENT_ID" : data["cert_chain"][i+1]
                        })
                    except IndexError:
                        chain_data.append({
                            "CERT_ID" : data["cert_chain"][i],
                            "CERT_PARENT_ID" : data["cert_chain"][i]
                        })

                insert_chain_statement = insert(CertChainRelation).values(chain_data).prefix_with('IGNORE')
                db.session.execute(insert_chain_statement)
                db.session.commit()
                self.queue.task_done()
