
import time
import select
import subprocess
import http.client

import redis
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from celery.app.task import Task
from datetime import datetime, timezone

from backend.celery.celery_app import celery_app
from backend.logger.logger import primary_logger
from backend.utils.exception import RetriveError
from backend.utils.network import resolve_host_dns
from backend.utils.domain import check_input_type
from backend.config.config_loader import ZGRAB2_PATH, DEFAULT_IP_BLACKLIST
from backend.config.scan_config import InputScanConfig, CTScanConfig
from backend.scanner.jarm_fp_utils import *
from backend.scanner.scan_manager import InputScanner, CTScanner
from backend.scanner.celery_save_task import input_scan_save_result

r = redis.Redis()

@celery_app.task(bind=True)
def launch_scan_task(self: Task, config_dict: dict):

    # get the scan task id for the scan
    # init config info for the scan
    # set up unique logger for the scan
    # set up monitor task for the scan
    if config_dict.get("input_list_file"):
        config = InputScanConfig.from_dict(config_dict)
        scanner = InputScanner(self.request.id, config)
    elif config_dict.get("ct_log_address"):
        config = CTScanConfig.from_dict(config_dict)
        scanner = CTScanner(self.request.id, config)
    else:
        primary_logger.error(f"Can not distinguish the config type: {config_dict}")

    scanner.start()
    return True


@celery_app.task
def single_scan_task(destination : str, config_dict: dict):

    scan_config : InputScanConfig = InputScanConfig.from_dict(config_dict)

    if scan_config.enable_jarm:
        jarm = ""
        # Select the packets and formats to send
        # Array format = [destination_host,scan_config.scan_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
        tls1_2_forward = [destination, scan_config.scan_port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
        tls1_2_reverse = [destination, scan_config.scan_port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
        tls1_2_top_half = [destination, scan_config.scan_port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
        tls1_2_bottom_half = [destination, scan_config.scan_port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
        tls1_2_middle_out = [destination, scan_config.scan_port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
        tls1_1_middle_out = [destination, scan_config.scan_port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
        tls1_3_forward = [destination, scan_config.scan_port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
        tls1_3_reverse = [destination, scan_config.scan_port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
        tls1_3_invalid = [destination, scan_config.scan_port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
        tls1_3_middle_out = [destination, scan_config.scan_port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
        # Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
        # Possible cipher lists: ALL, NO1.3
        # GREASE: either NO_GREASE or GREASE
        # APLN: either APLN or RARE_APLN
        # Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
        # Possible Extension order: FORWARD, REVERSE
        queue = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]
    else:
        jarm = None
        queue = []

    
    # first we gonna check if the dest is IP or domain
    dest_type = check_input_type(destination)
    if dest_type == "IP address":
        ip_queue = [destination]
        destination = None
    elif dest_type == "Domain":
        # if we met wildcard domain, then we scan its root domain instead
        if destination.startswith("*."):
            destination = destination[2:]
        # resolve the host
        ipv4, ipv6 = resolve_host_dns(destination, dns_servers=['114.114.114.114'])
        ip_queue = ipv4 + ipv6
    else:
        primary_logger.error(f"Invalid input dest format: {destination}")
        return False
    
    # Iterate through all the IPs
    for destination_ip in ip_queue:

        primary_logger.debug(f"{destination} : {destination_ip}")
        # # Detect signal
        # if scan_config.crtl_c_event.is_set():
        #     # my_logger.info("Terminating scan thread because of Ctrl + C signal")
        #     return
        
        # Check blacklist
        if destination_ip in DEFAULT_IP_BLACKLIST:
            primary_logger.warning(f"{destination_ip} lies in IP blacklist, skips")
            continue

        # Assemble, send, and decipher each packet (if enabled jarm)
        for i, jarm_setting in enumerate(queue):
            payload = packet_building(jarm_setting)
            server_hello = send_packet(payload, destination_ip, scan_config.scan_port)

            # Deal with timeout error
            if server_hello == "TIMEOUT":
                jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
                break

            server_hello_ans = read_packet(server_hello)
            jarm += server_hello_ans
            iterate += 1
            if iterate < len(queue):
                jarm += ","

        # Fuzzy hash
        _jarm_hash = jarm_hash(jarm) if jarm else None

        # do handshake and save results
        process_target.delay(destination, destination_ip, scan_config.to_dict(), jarm, _jarm_hash)

    return True


@celery_app.task
def process_target(destination, destination_ip, scan_config, jarm, jarm_hash):
    # Now try to make ssl handshake, use blocking celery task
    primary_logger.debug(f"Processing on {destination} : {destination_ip}...")
    ssl_result = _do_ssl_handshake(destination, destination_ip, InputScanConfig.from_dict(scan_config))
    input_scan_save_result.delay({
        "destination_host": destination,
        "destination_ip": destination_ip,
        "scan_time" : datetime.now(timezone.utc).isoformat(),
        "jarm": jarm,
        "jarm_hash": jarm_hash,
        "ssl_result": ssl_result
    })


'''
    @Naive function for certificate retrieve in IP and Domain scans
    This function now do not resolve any DNS to get the IP, we pass the IP directly
'''
@celery_app.task
def _do_ssl_handshake(host : str, ip : str, scan_config : InputScanConfig):
    try:
        '''
            Well, OPENSSL.SSL.Connection only accepts socket.socket,
            we can not use socks.socksocket() from "socks" PySocks to set up proxy
            Instead, we use http.client.HTTPConnection and set_tunnel to
            use the CONNECT method to initiate a tunnelled connection
        '''
        if scan_config.proxy_host and scan_config.proxy_port:
            proxy_conn = http.client.HTTPConnection(scan_config.proxy_host, scan_config.proxy_port, timeout=scan_config.scan_timeout)
            proxy_conn.set_tunnel(ip, scan_config.scan_port)
        else:
            proxy_conn = http.client.HTTPConnection(ip, scan_config.scan_port, timeout=scan_config.scan_timeout)

        proxy_conn.connect()
        proxy_socket = proxy_conn.sock

    # sometimes, this connect can fail (especially for ipv6 scenarios)
    # TODO: handle this case
    except OSError as e:
        tls_version = None
        tls_cipher = None
        cert_pem = []
        last_error = str(e)
    
        ssl_result = {
            "tls_version" : tls_version,
            "tls_cipher" : tls_cipher,
            "peer_certs" : cert_pem,
            "error" : last_error
        }
        # primary_logger.debug(ssl_result)
        return ssl_result

    try:
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
            if retry_count >= scan_config.max_retry:
                raise RetriveError
            try:
                primary_logger.debug(f"performing handshake on {host} : {ip}...")
                sock_ssl.do_handshake()
                break
            except SSL.WantReadError as e:
                # 等待套接字可读
                readable, _, _ = select.select([sock_ssl], [], [], scan_config.scan_timeout)
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
            
        '''
            SSL.SSL3_VERSION : 0,
            SSL.TLS1_1_VERSION : 1,
            SSL.TLS1_2_VERSION : 2,
            SSL.TLS1_3_VERSION : 3
        '''
        tls_version = sock_ssl.get_protocol_version()
        tls_cipher = sock_ssl.get_cipher_name()
    
        # Retrieve the peer certificate
        certs = sock_ssl.get_peer_cert_chain()
        cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
        # my_logger.info(f"Success fetching certificate for {host} : {len(certs)}")

    except RetriveError as e:
        # my_logger.error(f"Error fetching certificate for {host}: {last_error} {last_error.__class__}")
        tls_version = None
        tls_cipher = None
        cert_pem = []

    except Exception as e:
        # my_logger.error(f"Error fetching certificate for {host}: {e} {e.__class__}")
        tls_version = None
        tls_cipher = None
        cert_pem = []
        last_error = str(e)
    
    finally:
        proxy_socket.close()
        ssl_result = {
            "tls_version" : tls_version,
            "tls_cipher" : tls_cipher,
            "peer_certs" : cert_pem,
            "error" : last_error
        }
        # primary_logger.debug(ssl_result)
        return ssl_result


# External scan tools caller functions
# @DEPRECATED NOW
def run_zgrab2(input_file, output_file):
    command = [
        ZGRAB2_PATH,
        "--senders", 100,
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
