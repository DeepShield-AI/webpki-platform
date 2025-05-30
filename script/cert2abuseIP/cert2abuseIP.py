
# give an X509 cert in pem format or cert_sha256, find all the abuse IP address that related to this cert

import sys
import json
import ipaddress
from backend.celery.celery_db_pool import engine_cert, engine_tls

# load all abuse IP from the file
with open("blacklist_20250529.json", "r", encoding='utf-8-sig') as bl:
    abuse_records = json.load(bl)
    data = abuse_records["data"]

    ip_abuse_data = {}
    for record in data:
        ip_abuse_data[record["ipAddress"]] = record["countryCode"]

with open("blacklist_20250530.json", "r", encoding='utf-8-sig') as bl:
    abuse_records = json.load(bl)
    data = abuse_records["data"]

    for record in data:
        ip_abuse_data[record["ipAddress"]] = record["countryCode"]

with open("blacklist_plain_20250530", "r", encoding='utf-8-sig') as bl:
    plain_ip_data = []
    for line in bl:
        plain_ip_data.append(line.strip())

with open("DROP_v4_20250530.json", "r", encoding='utf-8-sig') as bl:
    drop_data = {}
    for line in bl:
        try:
            _json = json.loads(line)
            # print(_json)
            drop_data[ipaddress.ip_network(_json["cidr"])] = _json["sblid"]
        except:
            pass

# go through the cert table
def find_ip_by_cert_sha256(cert_sha256):

    conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    query = f"""
        SELECT * FROM tlshandshake
        WHERE JSON_CONTAINS (cert_hash_list, %s)
        LIMIT 200
    """
    cursor.execute(query, (json.dumps([cert_sha256]), ))
    rows = cursor.fetchall()
    cursor.close()

    return [row[2] for row in rows]


def filter_abuse_ip(ip_set):
    filtered_ip_set = []
    for ip in ip_set:
        if ip in plain_ip_data:
            filtered_ip_set.append(ip)
        if ip in ip_abuse_data:
            filtered_ip_set.append((ip, ip_abuse_data[ip]))
    return filtered_ip_set


def filter_drop_ip(ip_set):
    filtered_ip_set = []
    for ip in ip_set:
        _ip = ipaddress.ip_address(ip)
        for _network in drop_data:
            if _ip in _network:
                filtered_ip_set.append((ip, drop_data[_network]))

    return filtered_ip_set

def main():
    cert_sha = sys.argv[1]
    ips = find_ip_by_cert_sha256(cert_sha)
    print("IP Search Result:")
    print(f"\t{ips}")

    filtered_ips = filter_abuse_ip(ips)
    print("IPs in the AbuseIPDB:")
    print(f"\t{filtered_ips}")

    filtered_ips = filter_drop_ip(ips)
    print("IPs in the DROP:")
    print(f"\t{filtered_ips}")


if __name__ == "__main__":
    main()

# 32f6de3c6b44e87a38f93f49e82a92d99265eea7f751ad0b48fb64ef713c183c
