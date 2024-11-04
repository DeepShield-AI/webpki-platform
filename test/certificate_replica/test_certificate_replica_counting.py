
import sys
sys.path.append(r"D:\global_ca_monitor")

import json
from app.analyzer.certificate_replicas.replica_counting import ReplicaCounting
from app.utils.domain_lookup import DomainRank
# from app.analyzer.certificate_replicas.overlap_analysis import OverlapAnalysis
# from app.analyzer.certificate_replicas.issuer_analysis import IssuerAnalysis
# from app.analyzer.certificate_replicas.pub_key_analysis import PubKeyAnalysis

analyzer = ReplicaCounting()
test_fqdn = "www.example.com"
test_set = set([
    "www.example.net",
    "www.taobao.com",
    "a.example.com",
    "com",
    "example.com",
    "www.example.com",
    "sub.www.example.com",
    "*",
    "*.com",
    "*.example.com",
    "*.www.example.com",
    "*.www.www.example.com"
])

template_set = analyzer.compute_san_template(test_fqdn, test_set)
print(sorted(template_set))

analyzer.start()

# # print result
# with open("2K_out.txt", "w") as f:
#     for group in analyzer.counting_dict.values():
#         count = group.analyze_group()

#         if count > 0:
#             d = {
#                 "Reg" : group.reg_domain_name,
#                 "Count" : count,
#                 "Overlap_Day" : OverlapAnalysis().analyze_group(group)[1],
#                 "Overlap_Percent" : OverlapAnalysis().analyze_group(group)[0],
#                 "Issuer_cn" : IssuerAnalysis().analyze_group(group)[0],
#                 "Issuer_org" : IssuerAnalysis().analyze_group(group)[1],
#                 "Pub_key" : PubKeyAnalysis().analyze_group(group)
#             }
#             json.dump(d, f, indent=4)
