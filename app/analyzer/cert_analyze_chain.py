
import os
import json
import threading
from threading import Lock
from queue import Queue
from datetime import datetime, timezone
from OpenSSL import crypto

from sqlalchemy.dialects.mysql import insert
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from cryptography.hazmat.primitives.asymmetric import types, padding

from app import app, db
from ..logger.logger import my_logger
from ..models import CaCertStore, CertChainRelation, DomainTrustRelation
from ..utils.cert import (
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)

class CertScanChainAnalyzer():

    def __init__(self, x509_store_path = r"/data/ct_log_data") -> None:
        self.x509_store_path = x509_store_path
        self.cert_store = crypto.X509Store()

        for dir in os.scandir(self.x509_store_path):
            if os.path.isdir(dir.path):
                self.unique_ca_certs_file = os.path.join(dir.path, "unique_ca_certs")
                try:
                    with open(self.unique_ca_certs_file, 'r') as f:
                        cert_data = f.read()

                    certificates = cert_data.split("-----END CERTIFICATE-----\n")
                    for cert in certificates:
                        if "-----BEGIN CERTIFICATE-----" in cert:
                            cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                            self.cert_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert))

                    my_logger.info(f"Load {len(certificates)} CA certs from {dir.path}")
                except FileNotFoundError:
                    pass

    # TODO: handle cross-sign and multiple parent CA stuff in the future
    def build_verified_chain(self, cert):
        try:
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            store_ctx = crypto.X509StoreContext(self.cert_store, x509_cert)
            chain = store_ctx.get_verified_chain()
            return [crypto.dump_certificate(crypto.FILETYPE_PEM, c).decode('utf-8') for c in chain]

        except crypto.X509StoreContextError as e:
            my_logger.error(f"Cert chain analysis failed for cert {e.certificate.get_subject().commonName}...")
            return None

    '''
        From GPT
    '''
    def find_all_chains(self, target_cert, ca_store):
        """尝试构建所有可能的证书链"""
        chains = []

        def build_chain(cert, chain):
            # 如果当前证书是根证书，终止链
            if cert.get_subject() == cert.get_issuer():
                chains.append(chain + [cert])
                return

            # 在存储中查找所有可能的 Issuer
            for ca_cert in ca_store:
                if ca_cert.get_subject() == cert.get_issuer():
                    build_chain(ca_cert, chain + [cert])

        # 从目标证书开始构建
        build_chain(target_cert, [])
        return chains

    def verify_chain_signature(self, chain):
        """验证证书链的完整性"""
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer_cert = chain[i + 1]
            try:
                issuer_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception as e:
                return False
        return True


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
