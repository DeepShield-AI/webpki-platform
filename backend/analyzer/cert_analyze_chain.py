
import os
import json
import threading
from threading import Lock
from queue import Queue
from datetime import datetime, timezone

from sqlalchemy.dialects.mysql import insert
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from OpenSSL.crypto import (
    X509,
    X509Name,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    Error,
    load_certificate,
    dump_certificate,
    FILETYPE_PEM,
)

from backend import app, db
from ..config.analysis_config import CA_CERT_DIR, TRUST_ROOT_DIR
from ..logger.logger import my_logger
from ..models import CaCertStore, CertChainRelation, DomainTrustRelation
from ..utils.cert import (
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)

class CertChainAnalyzer():

    def __init__(self) -> None:
        self.trust_root_store = X509Store()
        self.untrust_ca_store = set()

        # load all CCADB trusted root
        for file in os.scandir(TRUST_ROOT_DIR):
            if os.path.isfile(file.path):
                self.trust_root_store.load_locations(file.path)

        # prepare untrusted but stored ca certs from CT
        for dir in os.scandir(CA_CERT_DIR):
            if os.path.isdir(dir.path):
                self.unique_ca_certs_file = os.path.join(dir.path, "unique_ca_certs")
                with open(self.unique_ca_certs_file, 'r') as f:
                    cert_data = f.read()

                certificates = cert_data.split("-----END CERTIFICATE-----\n")
                for cert in certificates:
                    if "-----BEGIN CERTIFICATE-----" in cert:
                        cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                        self.untrust_ca_store.add(load_certificate(FILETYPE_PEM, cert))
                my_logger.info(f"Load {len(certificates)} CA certs from {dir.path}")

    '''
        Function 1: give one leaf (ca) certificate, find all possible cross-sign ca certs (not path now)
        TODO: replace parent to path and give label trust/untrusted
    '''
    def find_cross_sign_certs_from_store(self, cert : str, all = False):
        cross_sign_certs_num = 0

        try:
            x509_cert = load_certificate(FILETYPE_PEM, cert)
            issuer = x509_cert.get_issuer().der()

            for ca_cert in self.untrust_ca_store:
                ca_cert : X509
                subject = ca_cert.get_subject().der()

                if issuer == subject:
                    # possible parent
                    print("see")
                    # is_parent = self.verify_parent(x509_cert, ca_cert)
                    # if is_parent:
                    cross_sign_certs_num += 1

        except X509StoreContextError as e:
            my_logger.error(f"Cert chain analysis failed for cert {e.certificate.get_subject().commonName}...")
        except Exception as e:
            my_logger.error(f"{e}")
        finally:
            return cross_sign_certs_num

    def verify_parent(self, cert, issuer):
        # build single context to 
        # in this internal stage, we assume the issuer (even if non-root cert) can be trusted
        # so that the verify_certificate() can pass
        try:
            parent_store = X509Store()
            parent_store.add_cert(issuer)
            store_ctx = X509StoreContext(parent_store, cert)
            store_ctx.verify_certificate()
            return True
        except X509StoreContextError as e:
            return False

    '''
        Function 2: Verify current cert chain from scan and rebuild if possible
        TODO: rebuild chain and return the best/all selection(s)
        顺序混乱 - 调整顺序
        完整且可信
        完整但不可信
        不完整（缺中间、缺根）
        多余证书
    '''
    def verify_and_rebuild_cert_chain(self, cert_chain : list[str]):
        if not cert_chain: return None

        try:
            parent_store = X509Store()
            for cert in cert_chain:
                parent_store.add_cert(load_certificate(FILETYPE_PEM, cert))
            store_ctx = X509StoreContext(parent_store, load_certificate(FILETYPE_PEM, cert_chain[0]))
            store_ctx.verify_certificate()
            return True

        except X509StoreContextError as e:
            # print(len(cert_chain))
            # my_logger.error(f"Cert chain analysis failed for cert {e.certificate.get_subject().commonName}...")
            return False

    # @TODO use this instead
    def validate_and_order_cert_chain(self, cert_chain):
        """
        验证给定的证书链的有效性，并尝试修复其顺序或补全缺失证书。

        参数:
            cert_chain (list): 证书链，包含多个 X509 对象，可能顺序错误或不完整。
            x509_store (X509Store): 用于验证和补全证书链的信任存储。

        返回:
            list: 一个按顺序排列的有效证书链（从叶子到根），如果成功。
            None: 如果无法构建有效的证书链。

        异常:
            Exception: 如果验证失败或无法补全证书链。
        """

        # check and rebuild cert chain order
        try:
            # 建立颁发者到证书的映射
            issuer_to_cert = {cert.get_issuer().der() : cert for cert in cert_chain}

            # 构造链：从叶子开始，尝试找到匹配的颁发者
            ordered_chain = [cert_chain[0]]  # 从叶子证书开始
            current_cert = cert_chain[0]

            while True:
                issuer = current_cert.get_issuer().der()
                if issuer in issuer_to_cert:
                    next_cert = issuer_to_cert[issuer]
                    ordered_chain.append(next_cert)
                    current_cert = next_cert
                else:
                    break

            # 验证并返回重组的链
            ordered_chain = self.build_chain(ordered_chain)
            return ordered_chain
        except Exception:
            pass

        # 尝试使用信任存储中的证书补全链
        try:
            # 从信任存储补全链
            extended_chain = cert_chain[:]
            store_certs = []

            # 遍历存储的证书，添加到链中
            for i in range(self.trust_root_store.get_count()):
                store_certs.append(x509_store.get_cert(i))
            issuer_to_cert.update({cert.get_issuer().der(): cert for cert in store_certs})

            # 构造完整链
            ordered_chain = [cert_chain[0]]
            current_cert = cert_chain[0]

            while True:
                issuer = current_cert.get_issuer().der()
                if issuer in issuer_to_cert:
                    next_cert = issuer_to_cert[issuer]
                    if next_cert not in ordered_chain:
                        ordered_chain.append(next_cert)
                        current_cert = next_cert
                    else:
                        break
                else:
                    break

            # 验证补全后的链
            ordered_chain = self.build_chain(ordered_chain)
            return ordered_chain
        except Exception:
            pass

        # 最后一步：如果所有尝试都失败，返回错误
        raise Exception("Failed to construct a valid certificate chain.")


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
