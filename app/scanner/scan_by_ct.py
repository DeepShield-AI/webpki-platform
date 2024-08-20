
'''
    Created on 01/17/24
    Collect CT log entries and parse the certificates
'''

import os
import json
import time
import base64
import requests
import threading

from typing import Dict
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timezone
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.dialects.mysql import insert

from app import db, app
from ..parser.ct_parser import *
from .scan_base import Scanner, ScanStatusData
from ..config.scan_config import CTScanConfig
from ..utils.type import ScanType, ScanStatusType
from ..utils.cert import get_cert_sha256_hex_from_str
from ..logger.logger import my_logger
from ..models import CertStoreRaw

class CTScanner(Scanner):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : CTScanConfig
        ) -> None:

        super().__init__(scan_id, start_time, scan_config)

        # scan settings from scan config
        self.ct_log_address = scan_config.CT_LOG_ADDRESS
        self.entry_start = scan_config.ENTRY_START
        self.entry_end = scan_config.ENTRY_END
        self.window_size = scan_config.WINDOW_SIZE

    # Each scan thread needs to take the last entry into account
    # Means to add -1 at the "end"
    def scan_thread(self, start_entry, end_entry):
        
        # check window_size fits the start and the end range
        assert((end_entry - start_entry) >= self.window_size)

        thread_result = {}
        loop_start = start_entry
        loop_end = start_entry + self.window_size
        log_server_request = f'https://{self.ct_log_address}/ct/v1/get-entries'

        while loop_start < end_entry:

            received_entries = []
            if loop_end < end_entry:
                params = {'start': loop_start, 'end': loop_end - 1}
            else:
                params = {'start': loop_start, 'end': end_entry - 1}

            retry_times = 0
            while retry_times < self.max_retry:
                try:
                    response = requests.get(log_server_request, params=params, verify=True, timeout=self.scan_timeout)
                except Exception as e:
                    # my_logger.warning(f"Exception {e} when requesting CT entries from {start} to {end}")
                    retry_times += 1
                    continue

                if response.status_code == 200:
                    received_entries = json.loads(response.text)['entries']

                    if len(received_entries) != self.window_size:
                        print(f"Length of response: {len(received_entries)}, expected {self.window_size}")
                        retry_times += 1
                        continue
                    else:
                        break
                else:
                    # my_logger.warning(f"Requesting CT entries from {start} to {end} failed.")
                    retry_times += 1
                    continue
            
            # Cache the received results
            rank = -1
            for entry in received_entries:
                rank += 1
                entry_number = loop_start + rank
                thread_result[entry_number] = {}

                leaf_cert = merkle_tree_header.parse(base64.b64decode(entry['leaf_input']))
                if leaf_cert.LogEntryType == "X509LogEntryType":
                    # We have a normal x509 entry
                    thread_result[entry_number]['type'] = "Cert"
                    cert_data_string = certificate.parse(leaf_cert.Entry).CertData
                    thread_result[entry_number]['leaf'] = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8')

                    # Parse the `extra_data` structure for the rest of the chain
                    extra_data = certificate_chain.parse(base64.b64decode(entry['extra_data']))
                    thread_result[entry_number]['chain'] = []
                    for cert in extra_data.Chain:
                        thread_result[entry_number]['chain'].append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

                else:
                    # We have a precert entry
                    thread_result[entry_number]['type'] = "Precert"
                    extra_data = pre_cert_entry.parse(base64.b64decode(entry['extra_data']))
                    thread_result[entry_number]['leaf'] = crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8')

                    thread_result[entry_number]['chain'] = []
                    for cert in extra_data.CertChain.Chain:
                        thread_result[entry_number]['chain'].append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

            # update scan_status
            with self.scan_status_data_lock:
                self.scan_status_data.scanned_entries += self.window_size
                self.scan_status_data.success_count += len(received_entries)
                self.scan_status_data.error_count += self.window_size - len(received_entries)

            loop_start = loop_end
            loop_end = loop_start + self.window_size

        # store the result into the file indicated by the storage_directory
        file_name = self.ct_log_address.replace('/', '-') + f"_{start_entry}" + f"_{end_entry}"
        self.save_results(file_name, thread_result)
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
            
            total = int((self.entry_end - self.entry_start) / self.thread_workload)
            self.progress_task = self.progress.add_task("[Waiting]", total=total)

            timer_thread = threading.Thread(target=self.async_update_scan_process_info)
            timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            timer_thread.start()

            my_logger.info(f"Scanning...")
            with ThreadPoolExecutor(max_workers=self.max_threads_alloc) as executor:
                start = self.entry_start
                while start < self.entry_end:
                    end = start + self.thread_workload
                    if end < self.entry_end:
                        executor.submit(self.scan_thread, start, end)
                        # executor.submit(self.scan_thread, start, end).result()
                    else:
                        executor.submit(self.scan_thread, start, self.entry_end)
                        # executor.submit(self.scan_thread, start, self.entry_end).result()
                    start = end

                executor.shutdown(wait=True)
                my_logger.info("All threads finished.")
        
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
            self.scan_status_entry.SCANNED_RNTRIES = self.scan_status_data.scanned_entries
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()


    def save_results(self, file_name, cert_result : Dict):

            my_logger.info(f"Saving {len(cert_result.keys())} results...")
            with open(os.path.join(self.storage_dir, file_name), 'w') as f:
                json.dump(cert_result, f, indent=4)

        # with app.app_context():
        #     cert_data_to_insert = []
        #     try:
        #         insert_cert_raw_statement = insert(CertStoreRaw).values(cert_data_to_insert).prefix_with('IGNORE')
        #         db.session.execute(insert_cert_raw_statement)
        #         db.session.commit()
        #     except Exception as e:
        #         my_logger.error(f"Error insertion CT Scan data: {e} \n {e.with_traceback()}")
