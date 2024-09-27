
'''
    Created on 01/17/24
    Collect CT log entries and parse the certificates
'''

import os
import json
import time
import math
import base64
import requests
import threading
import signal
from queue import Queue
from threading import Lock
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


    def save_results(self):
        while not self.crtl_c_event.is_set():
            data = self.data_queue.get()
            if data is None:  # Poison pill to shut down the thread
                my_logger.info("Poision detected")
                break

            save_file_path = os.path.join(self.storage_dir, data["save_file_name"])
            data_to_be_stored = data["data"]
            my_logger.info(f"Saving {len(data_to_be_stored.keys())} results to {save_file_path}")

            try:
                with open(save_file_path, 'w') as f:
                    json.dump(data_to_be_stored, f)
            except Exception as e:
                my_logger.error(f"Save {save_file_path} failed, got exception {e}")
                pass

            self.data_queue.task_done()
            my_logger.info(f"Finished saving {len((data_to_be_stored.keys()))} results to {save_file_path}")
        my_logger.info("Thread for saving results finishes normally")


    def save_ca_certs(self):
        while not self.crtl_c_event.is_set():
            ca_cert = self.ca_cert_queue.get()
            if ca_cert is None:  # Poison pill to shut down the thread
                my_logger.info("Poision detected")
                break

            try:
                with open(self.unique_ca_certs_file, 'a') as f:
                    f.write(ca_cert)
            except Exception as e:
                my_logger.error(f"Save ca cert {get_cert_sha256_hex_from_str(ca_cert)} failed, got exception {e}")
                pass

            self.ca_cert_queue.task_done()
        my_logger.info("Thread for CA certs finishes normally")


    # Each scan thread needs to take the last entry into account
    # Means to add -1 at the "end"
    def scan_thread(self, start_entry, end_entry):

        # Currently, there exists WHOLE thread results missing,
        # so we need to try to catch all possible exceptions (as executor.subit() won't give any exception
        # output if you do not add .result() at the end......)
        try:
        
            # check window_size fits the start and the end range
            # assert((end_entry - start_entry) >= self.window_size)
            my_logger.info(f"Start thread for {start_entry} to {end_entry}")

            thread_result = {}
            loop_start = start_entry
            loop_end = start_entry + self.window_size
            log_server_request = f'https://{self.ct_log_address}/ct/v1/get-entries'

            while loop_start < end_entry:

                # Detect signal
                if self.crtl_c_event.is_set():
                    my_logger.info("Terminating scan thread because of Ctrl + C signal")
                    return

                received_entries = []
                if loop_end >= end_entry:
                    loop_end = end_entry

                retry_times = 0
                params = {'start': loop_start, 'end': loop_end - 1}
                while retry_times <= self.max_retry:
                    try:
                        response = requests.get(log_server_request, params=params, verify=True, timeout=self.scan_timeout)
                    except Exception as e:
                        # my_logger.warning(f"Exception {e} when requesting CT entries from {loop_start} to {loop_end}")
                        retry_times += 1
                        time.sleep(2 * retry_times)  # 指数退避策略
                        continue

                    if response.status_code == 200:
                        received_entries += json.loads(response.text)['entries']

                        if (len(received_entries) < (loop_end - loop_start)):
                            print(f"Length of response: {len(received_entries)}, expected {loop_end - loop_start}")

                            # This case, we try to get the remain entries
                            params = {'start': loop_start + len(received_entries), 'end': loop_end - 1}
                            retry_times += 1
                            time.sleep(2 * retry_times)  # 指数退避策略
                            continue
                        else:
                            # print(f"Get all {loop_end - loop_start} entries")
                            break
                    
                    # 429 -> too many requests，read Retry-After and wait
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", 1))
                        # my_logger.warn(f"Received 429, retrying after {retry_after} seconds...")
                        time.sleep(retry_after)
                        continue
                    else:
                        my_logger.warning(f"Requesting CT entries from {loop_start} to {loop_end} get {response.status_code}.")
                        retry_times += 1
                        time.sleep(2 * retry_times)  # 指数退避策略
                        continue
                
                # If the collection fails, we log it here
                if retry_times > self.max_retry:
                    my_logger.error(f"Requesting CT entries from {loop_start} to {loop_end} failed after {self.max_retry} times.")

                # Cache the received results
                rank = -1
                for entry in received_entries:
                    rank += 1
                    entry_number = loop_start + rank
                    thread_result[entry_number] = {}

                    leaf_cert = merkle_tree_header.parse(base64.b64decode(entry['leaf_input']))
                    ct_timestamp = leaf_cert.Timestamp
                    thread_result[entry_number]['timestamp'] = ct_timestamp

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

                    # Compress the cert chain
                    new_chain = []
                    for cert in thread_result[entry_number]['chain']:
                        sha256_hash = get_cert_sha256_hex_from_str(cert)
                        new_chain.append(sha256_hash)
                        if sha256_hash not in self.ca_sha_256_set:
                            with self.ca_sha_256_set_lock:
                                self.ca_sha_256_set.add(sha256_hash)
                                self.ca_cert_queue.put(cert)
                    
                    # Replace the chain with its SHA-256 hash
                    thread_result[entry_number]['chain'] = new_chain

                # update scan_status
                with self.scan_status_data_lock:
                    self.scan_status_data.scanned_entries += self.window_size
                    self.scan_status_data.success_count += len(received_entries)
                    self.scan_status_data.error_count += self.window_size - len(received_entries)

                loop_start = loop_end
                loop_end = loop_start + self.window_size

            # store the result into the file indicated by the storage_directory
            file_name = self.ct_log_name + f"_{start_entry}" + f"_{end_entry}"
            self.data_queue.put({
                "save_file_name" : file_name,
                "data" : thread_result
            })

            my_logger.info(f"Put data to {file_name} into queue")
            self.progress.update(self.progress_task, description=f"[green]Completed: {self.scan_status_data.success_count}, [red]Errors: {self.scan_status_data.error_count}")
            self.progress.advance(self.progress_task)
        
        except json.JSONDecodeError as e:
            my_logger.error(f"JSON decode error {e.msg} happens at {e.pos} in thread for {start_entry} to {end_entry}")
            thread_result_str = json.dumps(thread_result)
            error_position = e.pos

            # 打印错误位置附近的字符（比如前后50个字符）
            start_pos = max(0, error_position - 50)
            end_pos = min(len(thread_result_str), error_position + 50)

            my_logger.error(f"100 chars around the error position:")
            my_logger.error(f"BEFORE: {thread_result_str[start_pos:error_position]}")
            my_logger.error(f"AFTER: {thread_result_str[error_position:end_pos]}")

        except Exception as e:
            my_logger.error(f"Exception {e} happens in thread for {start_entry} to {end_entry}")
            pass


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:
            
            total = math.ceil((self.entry_end - self.entry_start) / self.thread_workload)
            self.progress_task = self.progress.add_task("[Waiting]", total=total)

            self.timer_thread = threading.Thread(target=self.async_update_scan_process_info)
            # self.timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.timer_thread.start()

            # Start the thread that saves processed data from the queue
            self.ca_certs_save_thread = threading.Thread(target=self.save_ca_certs)
            # self.ca_certs_save_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.ca_certs_save_thread.start()

            self.data_save_thread = threading.Thread(target=self.save_results)
            # self.data_save_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            self.data_save_thread.start()

            my_logger.info(f"Scanning...")
            with ThreadPoolExecutor(max_workers=self.max_threads_alloc) as executor:
                start = self.entry_start
                while start < self.entry_end:

                    # Check if there is signals
                    if self.crtl_c_event.is_set():
                        my_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                        break

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
        
            # Wait for all elements in queue to be handled
            self.ca_cert_queue.join()
            self.data_queue.join()

            # Send the poison pill to stop the saver thread
            self.ca_cert_queue.put(None)
            self.data_queue.put(None)
            self.ca_certs_save_thread.join()
            self.data_save_thread.join()

            # The timer thread will never terminates unless the flag is set
            self.crtl_c_event.set()
            self.timer_thread.join()

        if self.is_killed:
            my_logger.info(f"Scan Terminated")
            with self.scan_status_data_lock:
                self.scan_status_data.end_time = datetime.now(timezone.utc)
                self.scan_status_data.status = ScanStatusType.KILLED
        else:
            my_logger.info(f"Scan Completed")
            with self.scan_status_data_lock:
                self.scan_status_data.end_time = datetime.now(timezone.utc)
                self.scan_status_data.status = ScanStatusType.COMPLETED
        self.sync_update_scan_process_info()


    def terminate(self):
        my_logger.info("Terminating CT scan task...")
        self.crtl_c_event.set()  # 触发退出事件
        self.is_killed = True


    def pause(self):
        pass
    def resume(self):
        pass


    def async_update_scan_process_info(self):
        while not self.crtl_c_event.is_set():
            self.sync_update_scan_process_info()
            time.sleep(15)
        my_logger.info("Thread for tracking the scan status terminates normally")


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

        # with app.app_context():
        #     cert_data_to_insert = []
        #     try:
        #         insert_cert_raw_statement = insert(CertStoreRaw).values(cert_data_to_insert).prefix_with('IGNORE')
        #         db.session.execute(insert_cert_raw_statement)
        #         db.session.commit()
        #     except Exception as e:
        #         my_logger.error(f"Error insertion CT Scan data: {e} \n {e.with_traceback()}")
