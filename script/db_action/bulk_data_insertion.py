
import sys
sys.path.append(r"../../")

import os, json
from sqlalchemy.dialects.mysql import insert
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from app import app, db
from app.models import CertStore
from app.logger.logger import my_logger
from app.utils.cert import get_cert_sha256_hex_from_str

data = {}
input_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110"

def modify(certificate_base64):
    # 将 Base64 数据分割为每 64 个字符一行
    formatted_certificate = "\n".join([certificate_base64[i:i+64] for i in range(0, len(certificate_base64), 64)])
    # 添加 PEM 头和尾
    pem_certificate = f"-----BEGIN CERTIFICATE-----\n{formatted_certificate}\n-----END CERTIFICATE-----"
    return pem_certificate

if __name__ == "__main__":

    progress = Progress(
        TextColumn("[bold blue]{task.description}", justify="right"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),  # 添加预计剩余时间列
        transient=True  # 进度条完成后隐藏
    )

    progress_task = progress.add_task("[Waiting]")

    if os.path.isfile(input_file):
        with open(input_file, "r", encoding='utf-8') as file:
            print(f"Reading file: {input_file}")
            count = 0

            for line in file:
                json_obj = json.loads(line.strip())

                try:
                    cert = json_obj["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
                    pem = modify(cert["certificate"]["raw"])
                    chain_sha_256 = get_cert_sha256_hex_from_str(pem)
                    data[chain_sha_256] = pem

                    # chain = cert["chain"]
                    # for c in chain:
                    #     data[get_cert_sha256_hex_from_str(c["raw"])] = c["raw"]

                except Exception as e:
                    my_logger.debug(f"Domain has no cert received")

                count += 1
                progress.update(progress_task, description=f"[green]Completed: {count}")
                progress.advance(progress_task)

    with app.app_context():

        my_logger.info(f"Saving {len(list(data.keys()))} results...")

        for key, value in data.items():
            try:
                # many many primary key dupliates...
                # need to deal with Integrity Error with duplicate primary key pair with bulk_insert_mappings
                cert_data_to_insert = [{'CERT_ID' : key, 'CERT_RAW' : value}]
                insert_cert_raw_statement = insert(CertStore).values(cert_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_raw_statement)
                db.session.commit()

            except Exception as e:
                my_logger.error(f"Error insertion domain Scan data: {e} \n {e.with_traceback()}")
                pass
