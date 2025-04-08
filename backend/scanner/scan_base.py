
import time
import threading
import select
import socket
import socks
import codecs
import ipaddress
import http.client
import subprocess

from abc import ABC, abstractmethod
from threading import Lock
from rich.progress import Progress, TaskID
from rich.console import Console

from datetime import datetime, timezone
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from dataclasses import dataclass

from .jarm_fp_utils import *
from backend.config.config_loader import ZGRAB2_PATH, ZMAP_PATH
from backend.config.scan_config import ScanConfig
from backend.utils.type import ScanType, ScanStatusType
from backend.utils.exception import RetriveError
from backend.logger.logger import primary_logger
from backend.models import ScanStatus


@dataclass
class ScanStatusData():

    '''
        Scan Status Data contains all info for ScanStatus db model
        use this soly for updating ScanStatus model
    '''

    start_time : datetime = datetime.now(timezone.utc)
    end_time : datetime = None
    status : ScanStatusType = ScanStatusType.RUNNING

    scanned_domains : int = 0
    scanned_ips : int = 0
    scanned_entries : int = 0
    scanned_certs : int = 0

    success_count : int = 0
    error_count : int = 0


tls_version_map = {
    SSL.SSL3_VERSION : 0,
    SSL.TLS1_1_VERSION : 1,
    SSL.TLS1_2_VERSION : 2,
    SSL.TLS1_3_VERSION : 3
}

class Scanner(ABC):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : ScanConfig,
        ) -> None:

        # scan settings from scan config
        self.scan_id = scan_id
        self.scan_name = scan_config.SCAN_PROCESS_NAME
        self.scan_start_time = start_time

        self.storage_dir = scan_config.STORAGE_DIR
        self.max_threads_alloc = scan_config.MAX_THREADS_ALLOC
        self.thread_workload = scan_config.THREAD_WORKLOAD

        self.proxy_host = scan_config.PROXY_HOST
        self.proxy_port = scan_config.PROXY_PORT
        self.scan_timeout = scan_config.SCAN_TIMEOUT
        self.max_retry = scan_config.MAX_RETRY

        self.scan_status_data_lock = Lock()
        self.scan_status_data = ScanStatusData(start_time=start_time)
        self.scan_status_entry : ScanStatus = ScanStatus.query.filter_by(ID=scan_id).first()

        # Console
        # @Debug only
        self.progress = Progress()
        self.progress_task = TaskID(-1)
        self.console = Console()

        # Crtl+C and other signals
        self.crtl_c_event = threading.Event()
        self.is_killed = False


    '''
        @Naive function for certificate retrieve in IP and Domain scans
        This function now do not resolve any DNS to get the IP, we pass the IP directly
    '''
    def fetch_raw_cert_chain(self, host : str, ip, port=443, proxy_host="127.0.0.1", proxy_port=33210):
        try:
            '''
                Well, OPENSSL.SSL.Connection only accepts socket.socket,
                we can not use socks.socksocket() from "socks" PySocks to set up proxy
                Instead, we use http.client.HTTPConnection and set_tunnel to
                use the CONNECT method to initiate a tunnelled connection
            '''
            if proxy_host and proxy_port:
                proxy_conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=self.scan_timeout)
                proxy_conn.set_tunnel(ip, port)
            else:
                proxy_conn = http.client.HTTPConnection(ip, port, timeout=self.scan_timeout)

            proxy_conn.connect()
            proxy_socket = proxy_conn.sock

            # We will construct multiple CHs in the futrue with a custom TLS library
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE)
            ctx.set_options(SSL.OP_NO_RENEGOTIATION)
            ctx.set_options(SSL.OP_IGNORE_UNEXPECTED_EOF)
            ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
            ctx.set_min_proto_version(SSL.SSL3_VERSION)

            # my_logger.info(f"Getting certs from {host}...")
            sock_ssl = SSL.Connection(ctx, proxy_socket)
            if host:
                sock_ssl.set_tlsext_host_name(host.encode())  # SNI is here
            sock_ssl.set_connect_state()

            retry_count = 0
            last_error = None
            while True:
                if retry_count >= self.max_retry:
                    raise RetriveError
                try:
                    sock_ssl.do_handshake()
                    break
                except SSL.WantReadError as e:
                    # 等待套接字可读
                    readable, _, _ = select.select([sock_ssl], [], [], self.scan_timeout)
                    # Timeout occurs
                    if not readable:
                        last_error = e
                        retry_count += 1
                        continue
                except SSL.SysCallError as e:
                    last_error = e
                    retry_count += 1
                    time.sleep(0.1)
                    continue

            # Retrieve the peer certificate
            certs = sock_ssl.get_peer_cert_chain()
            cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
            # my_logger.info(f"Success fetching certificate for {host} : {len(certs)}")

            tls_version = tls_version_map[sock_ssl.get_protocol_version()]
            tls_cipher = sock_ssl.get_cipher_name()
            proxy_socket.close()
            return cert_pem, None, tls_version, tls_cipher
        
        except RetriveError as e:
            # my_logger.error(f"Error fetching certificate for {host}: {last_error} {last_error.__class__}")
            proxy_socket.close()
            # print("ERROR")
            return [], f"{last_error} {last_error.__class__}", None, None

        except Exception as e:
            # my_logger.error(f"Error fetching certificate for {host}: {e} {e.__class__}")
            try:
                proxy_socket.close()
            except UnboundLocalError:
                pass
            return [], f"{e} {e.__class__}", None, None


    # Send the assembled client hello using a socket
    # We directly connect to destination ip as the SNI extension has already added to the CH packet
    def send_packet(self, packet, destination_ip, destination_port, proxyhost=None, proxyport=None):
        try:
            # Determine if the input is an IP
            if (type(ipaddress.ip_address(destination_ip)) != ipaddress.IPv4Address) and (type(ipaddress.ip_address(destination_ip)) != ipaddress.IPv6Address):
                primary_logger.error(f"Passing a non-IP string into the send_packet function: {destination_ip}")
                return None
        except Exception:
            primary_logger.error(f"Passing a non-IP string into the send_packet function: {destination_ip}")
            return None

        try:
            if ":" in destination_ip:
                if proxyhost and proxyport:
                    sock = socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.set_proxy(socks.SOCKS5, proxyhost, proxyport)
                else:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                sock.connect((destination_ip, destination_port, 0, 0))
            else:
                if proxyhost and proxyport:
                    sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.set_proxy(socks.SOCKS5, proxyhost, proxyport)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                sock.connect((destination_ip, destination_port))

            # Receive SH, however, this might now be complete SH
            sock.sendall(packet)
            server_hello_data = sock.recv(1484)
            
            '''
                This is where we make something new
                Ideas:
                    1. Receive more packets, and build FP based on that
                    2. Try to analyze certificates from the raw packet
            '''
            # certifiate_data = sock.recv(10000)
            
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return bytearray(server_hello_data)

        # Timeout errors result in an empty hash
        except socket.timeout as e:
            primary_logger.debug(f"Timeout when connecting {destination_ip}...")
            sock.close()
            return "TIMEOUT"

        except Exception as e:
            primary_logger.debug(f"Exception {e} happens when connecting {destination_ip}...")
            try:
                sock.close()
            except UnboundLocalError:
                pass
            return None


    # If a packet is received, decipher the details
    def read_packet(self, data):
        try:
            if data == None:
                return "|||"
            jarm = ""

            # Server hello error
            if data[0] == 21:
                primary_logger.debug("Server hello error")
                selected_cipher = b""
                return "|||"

            # Check for server hello
            elif (data[0] == 22) and (data[5] == 2):
                server_hello_length = int.from_bytes(data[3:5], "big")
                counter = data[43]

                # Find server's selected cipher
                selected_cipher = data[counter+44:counter+46]

                # Find server's selected version
                version = data[9:11]

                # Format
                jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
                jarm += "|"
                jarm += codecs.encode(version, 'hex').decode('ascii')
                jarm += "|"

                # Extract extensions
                extensions = (extract_extension_info(data, counter, server_hello_length))
                jarm += extensions
                return jarm
            else:
                primary_logger.warning("Packet data[0] unknown number")
                return "|||"

        except Exception as e:
            primary_logger.error(f"Exception {e} happens when reading server hello packet, probably the packet is not server hello...")
            return "|||"


    # External scan tools caller functions
    def run_zmap(self, input_file, output_file):
        # handle input_file here
        if input_file: return
        
        zmap_command = [
            ZMAP_PATH,
            '-p', '443',
            '-o', output_file,
            '-B', '25M',    # can increase to 30M, but might cause server stuck
            # '-P', '2',      # send two probes to each target
            '-v', '3',      # set log level to 3, in the future to 0
            # '-q',           # run in quiet mode
            '0.0.0.0/0'     # scan all IPv4
        ]

        try:
            subprocess.run(zmap_command, capture_output=False, text=True, check=True)
            primary_logger.info(f"Zmap scan completed. Output saved to: {output_file}")
        except subprocess.CalledProcessError as e:
            primary_logger.error("Error occurred while running Zmap:")
            primary_logger.error(e.stderr)


    def run_zgrab2(self, input_file, output_file):
        command = [
            ZGRAB2_PATH,
            "--senders", f"{self.max_threads_alloc}",
            "--input-file", input_file,
            "--output-file", output_file,
            "tls"
        ]
        # Add heatbleed vulnerability check
        # command.append("--heartbleed")

        try:
            subprocess.run(command, capture_output=False, text=True, check=True)
            primary_logger.info(f"Zgrab2 scan completed. Output saved to: {output_file}")
        except subprocess.CalledProcessError as e:
            primary_logger.error("Error occurred while running Zgrab2:")
            primary_logger.error(e.stderr)

    '''
        @Methods for all types of scans
        @Use abstract methods here
    '''
    @abstractmethod
    def start(self):
        pass
    @abstractmethod
    def terminate(self):
        pass
    @abstractmethod
    def pause(self):
        pass
    @abstractmethod
    def resume(self):
        pass
    @abstractmethod
    def async_update_scan_process_info(self):
        pass
    @abstractmethod
    def sync_update_scan_process_info(self):
        pass

    # The scan data needs to be stored in files now
    @abstractmethod
    def save_results(self):
        pass
