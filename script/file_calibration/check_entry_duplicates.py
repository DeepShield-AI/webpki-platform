
import sys
sys.path.append(r"D:\global_ca_monitor")

import os
import json
from backend.utils.cert import get_cert_sha256_hex_from_str

load_dir = r'H:/oak2024'

for file_entry in os.scandir(load_dir):
    file_path = file_entry.path
    cert_sha256_set = set()

    if os.path.isfile(file_path):
        ok = True
        with open(file_path, "r") as file:
            data = json.load(file)

            for entry_id, entry_data in data.items():
                leaf_cert = entry_data["leaf"]

                sha256 = get_cert_sha256_hex_from_str(leaf_cert)
                if sha256 in cert_sha256_set:
                    print(f"Cert entry {entry_id} got duplicates...")
                    ok = False
                    continue
                cert_sha256_set.add(sha256)
        if ok:
            print(f"File {file_entry} has no duplicates")
