import csv
import ipaddress
from collections import defaultdict, Counter

input_path = "13-iot_ip.txt"

asn_csv_path = '/home/tianyuz23/data/pki-internet-platform/data/geolite2/geolite2-asn-ipv4.csv'
country_csv_path = '/home/tianyuz23/data/pki-internet-platform/data/geolite2/geolite2-country-ipv4.csv'

# 读取 ASN CSV
def read_asn_csv(file_path):
    data = []
    with open(file_path, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            start_ip = int(ipaddress.IPv4Address(row[0]))
            end_ip = int(ipaddress.IPv4Address(row[1]))
            asn = (row[2], row[3])  # ASN 和组织名称
            data.append((start_ip, end_ip, asn))
    return data

# 读取 country CSV
def read_country_csv(file_path):
    data = []
    with open(file_path, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            start_ip = int(ipaddress.IPv4Address(row[0]))
            end_ip = int(ipaddress.IPv4Address(row[1]))
            country = row[2]
            data.append((start_ip, end_ip, country))
    return data

# 查找 IP 所属 ASN
def find_asn(ip_int, asn_data):
    for start, end, asn in asn_data:
        if start <= ip_int <= end:
            return asn
    return None

# 查找 IP 所属 Country
def find_country(ip_int, country_data):
    for start, end, country in country_data:
        if start <= ip_int <= end:
            return country
    return None

# 主函数
def main():
    # 读取 CSV
    asn_data = read_asn_csv(asn_csv_path)
    # country_data = read_country_csv(country_csv_path)

    # 读取 IP 列表
    with open(input_path) as f:
        ips = [line.strip() for line in f if line.strip()]
        print(len(ips))

    asn_counter = Counter()
    # country_counter = Counter()

    for ip in ips:
        ip_int = int(ipaddress.IPv4Address(ip))
        asn = find_asn(ip_int, asn_data)
        # country = find_country(ip_int, country_data)
        if asn:
            asn_counter[asn] += 1
        # if country:
        #     country_counter[country] += 1

    # 输出全部统计结果
    print("ASN 出现次数统计：")
    for asn, count in asn_counter.most_common():  # 按出现次数从高到低排序
        print(f"ASN: {asn}: {count}")

    # print("\nCountry 出现次数统计：")
    # for country, count in country_counter.most_common():
    #     print(f"Country: {country}: {count}")

if __name__ == "__main__":
    main()
