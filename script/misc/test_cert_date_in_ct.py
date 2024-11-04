
import os
import json
from datetime import datetime

import sys
sys.path.append(r"D:\global_ca_monitor")

from app.parser.pem_parser import PEMParser


def check_entry_time(timestamp):

    timestamp_seconds = timestamp / 1000

    date_time = datetime.fromtimestamp(timestamp_seconds)
    formatted_date = date_time.strftime('%Y-%m-%d %H:%M:%S')

    print(f"Timestamp: {formatted_date}")


load_dir = r'H:/yeti2024'
file_name_list = os.listdir(load_dir)

for file_name in file_name_list:

    file_path = os.path.join(load_dir, file_name)
    if os.path.isfile(file_path):

        with open(file_path, "r") as file:
            print(f"Open file: {file_name}")
            data = json.load(file)

            for entry in data.values():
                pem_parser = PEMParser()
                leaf_cert_native = pem_parser.parse_pem_cert(entry['leaf'])
                check_entry_time(entry['timestamp'])
                print(f"Not Before Time: {leaf_cert_native.not_before}")
                print(f"Not After Time: {leaf_cert_native.not_after}")
                try:
                    print(f"Subject: {leaf_cert_native.subject}")
                except UnicodeEncodeError:
                    print(f"Subject: {[item.encode() for item in leaf_cert_native.subject]}")

