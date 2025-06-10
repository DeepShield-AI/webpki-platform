
# project Root Path

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent

ZLINT_PATH = os.path.join(ROOT_DIR, "zlint")
TRUST_ROOT_DIR = os.path.join(ROOT_DIR, "data/trust_roots")
CA_CERT_DIR = os.path.join(ROOT_DIR, "/data/ct_log_data")

# IP2LOCATIONDB1_DIR = r"/data/ip2location/db1/IP2LOCATION-LITE-DB1.BIN"
# IP2LOCATIONDB3_DIR = r"/data/ip2location/db3/IP2LOCATION-LITE-DB3.BIN"
# IP2LOCATIONASN_DIR = r"/data/ip2location/asn/IP2LOCATION-LITE-ASN.BIN"
