
import json

with open("13-spki_collision.json", "r") as f:
    my_dict = json.load(f)

len_list = []
for sha, id_list in my_dict.items():
    if len(id_list) > 1:
        len_list.append(len(id_list))
        # print(len(id_list), id_list[0])

# print(sorted(len_list, reverse=True))
for len in sorted(len_list):
    print(len)

'''
[
{'common_name': 'Vigor Router', 'country_name': 'TW', 'locality_name': 'HuKou', 'organization_name': 'DrayTek Corp.', 'state_or_province_name': 'HsinChu', 'organizational_unit_name': 'DrayTek Support', 'percentage': 0.04669725721721047},
{'common_name': 'FortiGate', 'organization_name': 'Fortinet Ltd.', 'percentage': 0.04630084060298032},
{'common_name': '192.168.168.168', 'country_name': 'US', 'locality_name': 'Sunnyvale', 'organization_name': 'HTTPS Management Certificate for SonicWALL (self-signed)', 'state_or_province_name': 'California', 'organizational_unit_name': 'HTTPS Management Certificate for SonicWALL (self-signed)', 'percentage': 0.04448579667857294},
{'common_name': 'unifi.local', 'percentage': 0.020278896825257423},
{'common_name': 'UbiquitiRouterUI', 'country_name': 'US', 'locality_name': 'New York', 'organization_name': 'Ubiquiti Inc.', 'state_or_province_name': 'New York', 'percentage': 0.00906729817796454},
{'common_name': 'technicolor.net', 'country_name': 'FR', 'locality_name': 'Cesson', 'organization_name': 'Technicolor', 'state_or_province_name': 'Brittany', 'organizational_unit_name': 'Connected Home', 'percentage': 0.0032154174721569853},
{'common_name': 'TP-Link', 'country_name': 'CN', 'locality_name': 'ShenZhen', 'state_or_province_name': 'ShenZhen', 'percentage': 0.003130348051032009},
{'common_name': 'TP-Link', 'country_name': 'CN', 'percentage': 0.0016142525377034907},
{'common_name': 'SynologyRouter', 'country_name': 'TW', 'email_address': 'product@synology.com', 'locality_name': 'Taipei', 'organization_name': 'Synology Inc.', 'state_or_province_name': 'Taiwan', 'organizational_unit_name': 'FTP Team', 'percentage': 0.0012026818565522913},
{'common_name': 'www.dlink.com', 'country_name': 'TW', 'locality_name': 'Taipei', 'organization_name': 'D-Link', 'state_or_province_name': 'Taiwan', 'organizational_unit_name': 'DHPD Dept.', 'percentage': 0.001183739272900981}
]
'''
