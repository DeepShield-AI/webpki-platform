
'''
    Update on 24/09/23
    Now domain scanner is integrated with Jarm
    The scanner can get Jarm TLS fingerprinting by adding scanning configuration
    Referenced with https://github.com/salesforce/jarm/blob/master/jarm.py
'''

import os
import csv
import json
import time
import hashlib
import threading
import subprocess

from datetime import datetime, timezone
from queue import PriorityQueue, Queue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.dialects.mysql import insert

from backend import db, app
from .jarm_fp_utils import *
from .scan_base import Scanner, ScanStatusData
from ..config.scan_config import DomainScanConfig, ZGRAB2_PATH
from ..config.ip_blacklist import IP_BLACKLIST
from ..utils.cert import get_cert_sha256_hex_from_str
from ..utils.type import ScanType, ScanStatusType
from ..utils.json import custom_serializer
from ..utils.network import resolve_host_dns
from ..logger.logger import my_logger


class DomainScanner(Scanner):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : DomainScanConfig,
        ) -> None:

        super().__init__(scan_id, start_time, scan_config)

        # scan settings from scan config
        self.scan_tool = scan_config.SCAN_TOOL
        self.input_csv_file = scan_config.INPUT_DOMAIN_LIST_FILE
        self.begin_num = scan_config.DOMAIN_INDEX_START
        self.end_num = scan_config.NUM_DOMAIN_SCAN - 1
        self.tls_fp_type = scan_config.TLS_FP_TYPE
        self.tls_fp_only = scan_config.TLS_FP_ONLY
        self.scan_port = scan_config.SCAN_PORT
        self.task_queue = PriorityQueue()
        self.data_queue = Queue()

        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

        # read domain list from the input file
        self.current_index = self.begin_num
        with open(self.input_csv_file, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)

            for row in reader:
                if self.current_index > self.end_num:
                    break

                try:
                    rank, host = int(row[0]), row[1]
                except Exception:
                    rank = 0
                    host = row[0]

                self.task_queue.put((rank, host))
                self.current_index += 1


    def scan_thread_with_custom_tls_fp(self, rank : int, destination_host : str):
        pass


    def scan_thread_with_jarm(self, rank : int, destination_host : str):

        original_host = destination_host
        if destination_host.startswith("*."):
            destination_host = destination_host[2:]

        # Select the packets and formats to send
        # Array format = [destination_host,self.scan_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
        tls1_2_forward = [destination_host, self.scan_port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
        tls1_2_reverse = [destination_host, self.scan_port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
        tls1_2_top_half = [destination_host, self.scan_port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
        tls1_2_bottom_half = [destination_host, self.scan_port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
        tls1_2_middle_out = [destination_host, self.scan_port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
        tls1_1_middle_out = [destination_host, self.scan_port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
        tls1_3_forward = [destination_host, self.scan_port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
        tls1_3_reverse = [destination_host, self.scan_port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
        tls1_3_invalid = [destination_host, self.scan_port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
        tls1_3_middle_out = [destination_host, self.scan_port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
        # Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
        # Possible cipher lists: ALL, NO1.3
        # GREASE: either NO_GREASE or GREASE
        # APLN: either APLN or RARE_APLN
        # Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
        # Possible Extension order: FORWARD, REVERSE
        queue = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]

        # First, resolve the host
        ipv4, ipv6 = resolve_host_dns(destination_host, dns_servers=['114.114.114.114'])
        
        # Iterate through all the IPs
        for destination_ip in ipv4 + ipv6:

            # Detect signal
            if self.crtl_c_event.is_set():
                # my_logger.info("Terminating scan thread because of Ctrl + C signal")
                return
            
            # Check blacklist
            if destination_ip in IP_BLACKLIST:
                my_logger.warning(f"{destination_ip} lies in IP blacklist, skips")
                continue

            jarm = ""

            # Assemble, send, and decipher each packet
            iterate = 0
            while iterate < len(queue):
                payload = packet_building(queue[iterate])
                server_hello = self.send_packet(payload, destination_ip, self.scan_port)

                # Deal with timeout error
                if server_hello == "TIMEOUT":
                    jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
                    break

                server_hello_ans = self.read_packet(server_hello)
                jarm += server_hello_ans
                iterate += 1
                if iterate < len(queue):
                    jarm += ","

            # Fuzzy hash
            _jarm_hash = jarm_hash(jarm)

            # Now try to get certificate chain
            if not self.tls_fp_only:
                cert_chain, e, tls_version, tls_cipher = self.fetch_raw_cert_chain(destination_host, destination_ip, proxy_host=None, proxy_port=None)
                cert_chain_sha256_hex = [get_cert_sha256_hex_from_str(cert) for cert in cert_chain]

                self.data_queue.put({
                    "rank" : rank,
                    "destination_host" : original_host,
                    "destination_ip" : destination_ip,
                    "jarm" : jarm,
                    "jarm_hash" : _jarm_hash,
                    "cert_chain" : cert_chain,
                    "cert_chain_hash" : cert_chain_sha256_hex
                })
            else:
                # print(original_host, _jarm_hash)
                self.data_queue.put({
                    "rank" : rank,
                    "destination_host" : original_host,
                    "destination_ip" : destination_ip,
                    "jarm_hash" : _jarm_hash
                })

        with self.scan_status_data_lock:
            self.scan_status_data.scanned_domains += 1
            self.scan_status_data.scanned_certs += 1

        self.progress.update(self.progress_task, description=f"[green]Completed: {self.scan_status_data.scanned_domains}, [red]Total: {self.total}")
        self.progress.advance(self.progress_task)


    def start(self):
        # Choose to use Zgrab2 or self_built tools
        if self.scan_tool == "zgrab2":
            output_file = os.path.join(
                self.storage_dir,
                self.scan_name.replace(" ", "_")
            )

            self.run_zgrab2(self.input_csv_file, output_file)

            with self.scan_status_data_lock:
                self.scan_status_data.end_time = datetime.now(timezone.utc)
                self.scan_status_data.status = ScanStatusType.COMPLETED
            self.sync_update_scan_process_info()

        elif self.scan_tool == "self":
            with Progress(
                TextColumn("[bold blue]{task.description}", justify="right"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),  # 添加预计剩余时间列
                transient=True  # 进度条完成后隐藏
            ) as self.progress:
                
                self.total = self.end_num - self.begin_num + 1
                self.progress_task = self.progress.add_task("[Waiting]", total=self.total)

                self.timer_thread = threading.Thread(target=self.async_update_scan_process_info)
                # self.timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
                self.timer_thread.start()

                self.data_save_thread = threading.Thread(target=self.save_results)
                # self.data_save_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
                self.data_save_thread.start()

                my_logger.info(f"Scanning...")
                with ThreadPoolExecutor(max_workers=self.max_threads_alloc) as executor:
                    while not self.task_queue.empty():
                        # Check if there is signals
                        if self.crtl_c_event.is_set():
                            my_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        index, host = self.task_queue.get()
                        if self.tls_fp_type == "jarm":
                            # my_logger.info(host)
                            executor.submit(self.scan_thread_with_jarm, index, host)
                            # executor.submit(self.scan_thread_with_jarm, index, host).result()
                        else:
                            executor.submit(self.scan_thread_with_custom_tls_fp, index, host)

                    # 等待所有线程完成
                    executor.shutdown(wait=True)
                    my_logger.info("All threads finished.")

                # Wait for all elements in queue to be handled
                self.data_queue.join()

                # Send the poison pill to stop the saver thread
                self.data_queue.put(None)
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

        else:
            my_logger.warning("Unrecognized scan tool")
            with self.scan_status_data_lock:
                self.scan_status_data.end_time = datetime.now(timezone.utc)
                self.scan_status_data.status = ScanStatusType.BACKEND_ERROR
            self.sync_update_scan_process_info()


    def terminate(self):
        my_logger.info("Terminating domain scan task...")
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
            self.scan_status_entry.SCANNED_DOMAINS = self.scan_status_data.scanned_domains
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()


    def save_results(self):
        count = 0
        index = 0
        window = 100000

        while not self.crtl_c_event.is_set():
            n = self.scan_name.replace(" ", "_")
            file_name = f"{n}_{index * window}_{(index + 1) * window}"
            save_file_path = os.path.join(self.storage_dir, file_name)
            my_logger.info(f"Opening {save_file_path}...")

            with open(save_file_path, 'w', encoding='utf-8') as f:
                while count <= window:
                    scan_entry = self.data_queue.get()

                    if scan_entry is None:  # Poison pill to shut down the thread
                        print("Poision detected")
                        return

                    try:
                        json_str = json.dumps(scan_entry, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                        f.write(json_str + '\n')
                    except Exception as e:
                        my_logger.error(f"Save {scan_entry} failed, got exception {e}")
                        pass

                    self.data_queue.task_done()
                    count += 1

                count = 0
                index += 1

        my_logger.info("Thread for saving results finishes normally")

