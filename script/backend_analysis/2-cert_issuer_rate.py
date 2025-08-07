
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

# tot_num = 0
# ca_issuer_rate = defaultdict(int)

# for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):
#     issuer = row[5]
#     if issuer:
#         issuer = json.loads(issuer)
#         # print(type(issuer), issuer)

#         if isinstance(issuer, dict):
#             cn = issuer.get("common_name")
#             ca_issuer_rate[str(cn)] += 1
#             tot_num += 1

# for k, v in ca_issuer_rate.items():
#     ca_issuer_rate[k] = v / tot_num

# with open("out.json", "w") as f:
#     json.dump(ca_issuer_rate, f, indent=2)



with open("out.json", "r") as f:
    my_dict = json.load(f)

top_100_keys = [k for k, v in sorted(my_dict.items(), key=lambda item: item[1], reverse=True)[:100]]

for key in top_100_keys:
    print(key, my_dict[key])

'''
CA 公司	原始占比总和
Let’s Encrypt（含 R11、R10、E5、E6、R3 等）	0.3224
私有 / 自签 / 设备证书（如 kubernetes、Traefik、TP-LINK、FortiGate、localhost 等）	0.1497
Amazon（含 M01～M04）	0.0615
Sectigo / Comodo 系列（含 Sectigo、COMODO、Encryption Everywhere、GoGetSSL、cPanel）	0.0607
DigiCert 系列（含 DigiCert、RapidSSL、Thawte、GeoTrust）	0.0391
Unknown / None	0.0269
GoDaddy / Starfield	0.0198
Microsoft Azure 系	0.0196
GlobalSign（含 AlphaSSL）	0.0113
TrustAsia / WoTrus / sslTrus	0.0108
ZeroSSL	0.0087
HydrantID	0.0033
Entrust	0.0029
Certum	0.0024
GÉANT	0.0022
JPRS	0.0020
Google Trust Services (GTS)	0.0007
Cybertrust Japan	0.0007
'''
