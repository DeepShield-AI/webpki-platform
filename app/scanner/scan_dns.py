
import csv
import time
import hashlib
import threading

from datetime import datetime, timezone
from queue import PriorityQueue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.dialects.mysql import insert

from app import db, app
from .scan_base import Scanner, ScanStatusData
from ..config.scan_config import DomainScanConfig
from ..utils.type import ScanType, ScanStatusType
from ..logger.logger import my_logger
from ..models import (
    ScanStatus, ScanData, CertScanMeta, CertStoreContent, CertStoreRaw
)


class DomainScanner(Scanner):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : CTScanConfig
        ) -> None:

        super().__init__(scan_id, start_time, scan_config)

        # scan settings from scan config
        self.ct_log_name = scan_config.CT_LOG_NAME
        self.ct_log_address = scan_config.CT_LOG_ADDRESS
        self.entry_start = scan_config.ENTRY_START
        self.entry_end = scan_config.ENTRY_END
        self.window_size = scan_config.WINDOW_SIZE

        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

        self.data_queue = Queue()
        self.ca_cert_queue = Queue()
        self.ca_sha_256_set_lock = Lock()
        self.ca_sha_256_set = set()

        # read old unique_ca_certs file and compute all the existing sha256
        self.unique_ca_certs_file = os.path.join(self.storage_dir, "unique_ca_certs")
        try:
            with open(self.unique_ca_certs_file, 'r') as f:
                cert_data = f.read()

            certificates = cert_data.split("-----END CERTIFICATE-----\n")
            for cert in certificates:
                if "-----BEGIN CERTIFICATE-----" in cert:
                    cert = cert + "-----END CERTIFICATE-----\n"  # 重新添加结尾
                    cert_sha256 = get_cert_sha256_hex_from_str(cert)
                    self.ca_sha_256_set.add(cert_sha256)

            my_logger.info(f"Load {len(certificates)} old CA certs")
        except FileNotFoundError:
            pass



    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : DomainScanConfig,
        ) -> None:

        super().__init__(scan_id, start_time, scan_config)

        # scan settings from scan config
        self.input_csv_file = scan_config.INPUT_DOMAIN_LIST_FILE
        self.begin_num = scan_config.DOMAIN_RANK_START
        self.end_num = scan_config.NUM_DOMAIN_SCAN - 1
        self.task_queue = PriorityQueue()
        self.load_tasks_into_queue()


    def load_tasks_into_queue(self):
        self.current_index = self.begin_num
        with open(self.input_csv_file, 'r') as file:
            reader = csv.reader(file)

            for row in reader:
                if self.current_index > self.end_num:
                    break

                rank, host = int(row[0]), row[1]
                self.task_queue.put((rank, host))
                self.current_index += 1


    def scan_thread(self, rank : int, host : str):
        
        '''
            To save VPN data, we first retrieve cert without VPN
            if this fails, we use VPN instead
            if both fail, we treat it as exact failure
            
            TODO: connect with different VPN nodes to see the data difference
        '''
        # ipv4, ipv6 = resolve_host_dns(host)
        ipv4 = []
        '''
            When we resolve DNS records, there might be many as CDN deploys
            TODO: for domain scan, try all ipv4 and ipv6 in the future
        '''
        if len(ipv4) > 0:
            host_ip = ipv4[0]
        else:
            host_ip = ""
        cert_chain, e, remote_ip, tls_version, tls_cipher = self.fetch_raw_cert_chain(host, host_ip, proxy_host=None, proxy_port=None)

        # print(len(cert_chain), e)
        if len(cert_chain) == 0:
            # my_logger.warning(f"{host} using VPN proxy data...")
            cert_chain, e, remote_ip, tls_version, tls_cipher = self.fetch_raw_cert_chain(host, host_ip, proxy_host=self.proxy_host, proxy_port=self.proxy_port)
        cert_chain_sha256_hex = [hashlib.sha256(cert.encode()).hexdigest() for cert in cert_chain]

        '''
            Right now, the IP address may not be right as we do not connect to IP address directly
            TODO: solve this problem and make sure the certificate matches IP address
        '''
        result = {'rank': rank, 'host': host, 'ip': remote_ip, 'error': e, 'certificate': cert_chain, 'sha256' : cert_chain_sha256_hex,
                  'tls_version' : tls_version, 'tls_cipher' : tls_cipher, 'scan_time' : datetime.now(timezone.utc)}

        with self.scan_status_data_lock:
            self.scan_status_data.scanned_domains += 1
            self.scan_status_data.scanned_certs += len(cert_chain)

            if e is not None:
                self.scan_status_data.error_count += 1
            else:
                self.scan_status_data.success_count += 1

        with self.cached_results_lock:
            self.cached_results.append(result)
        if len(self.cached_results) >= self.thread_workload:
            self.save_results()

        self.progress.update(self.progress_task, description=f"[green]Completed: {self.scan_status_data.success_count}, [red]Errors: {self.scan_status_data.error_count}")
        self.progress.advance(self.progress_task)


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:
            self.progress_task = self.progress.add_task("[Waiting]", total=self.end_num - self.begin_num)

            # asyncio.create_task(self.async_update_scan_process_info())
            timer_thread = threading.Thread(target=self.async_update_scan_process_info)
            timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            timer_thread.start()

            my_logger.info(f"Scanning...")
            with ThreadPoolExecutor(max_workers=self.max_threads_alloc) as executor:
                while not self.task_queue.empty():
                    index, host = self.task_queue.get()
                    executor.submit(self.scan_thread, index, host)
                # 等待所有线程完成
                executor.shutdown(wait=True)
                my_logger.info("All threads finished.")

        self.save_results()
        my_logger.info(f"Scan Completed")
        with self.scan_status_data_lock:
            self.scan_status_data.end_time = datetime.now(timezone.utc)
            self.scan_status_data.status = ScanStatusType.COMPLETED
        self.sync_update_scan_process_info()


    def terminate(self):
        pass
    def pause(self):
        pass
    def resume(self):
        pass


    def async_update_scan_process_info(self):

        while not self.progress.finished:
            # await asyncio.get_event_loop().run_in_executor(None, self.sync_update_scan_process_info)
            # await asyncio.sleep(5)
            self.sync_update_scan_process_info()
            time.sleep(5)


    def sync_update_scan_process_info(self):

        my_logger.info(f"Updating...")
        if self.scan_status_data.status == ScanStatusType.RUNNING:
            scan_time = (datetime.now(timezone.utc) - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.COMPLETED:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.KILLED:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        else:
            scan_time = -1

        with app.app_context():
            self.scan_status_entry.SCAN_TIME_IN_SECONDS = scan_time
            self.scan_status_entry.END_TIME = self.scan_status_data.end_time
            self.scan_status_entry.STATUS = self.scan_status_data.status.value
            self.scan_status_entry.SCANNED_DOMAINS = self.scan_status_data.scanned_domains
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()

import dns.resolver
import configparser

# 读取配置文件
config = configparser.ConfigParser()
config.read('dns_config.conf')

# 从配置文件中获取设置
nameservers = [ns.strip() for ns in config.get('DEFAULT', 'nameservers').split(',')]
timeout = config.getfloat('DEFAULT', 'timeout')
lifetime = config.getfloat('DEFAULT', 'lifetime')
record_types = [rt.strip() for rt in config.get('DEFAULT', 'record_types').split(',')]

# 创建并配置 Resolver 对象
resolver = dns.resolver.Resolver()
resolver.nameservers = nameservers
resolver.timeout = timeout
resolver.lifetime = lifetime

# 要查询的域名
domain = 'example.com'

# 逐一查询记录
for record_type in record_types:
    try:
        # 执行 DNS 查询
        answer = resolver.resolve(domain, record_type)
        print(f"\n{record_type} records for {domain}:")
        for rdata in answer:
            print(f"{rdata}")
    except dns.resolver.NoAnswer:
        print(f"No {record_type} record found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"{domain} does not exist.")
    except dns.resolver.Timeout:
        print(f"DNS query for {domain} timed out.")
    except dns.resolver.NoNameservers:
        print(f"No DNS servers available to resolve {domain}.")
