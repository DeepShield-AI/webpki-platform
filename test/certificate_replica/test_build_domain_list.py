
import sys
sys.path.append(r"D:\global_ca_monitor")

import time
from backend.analyzer.certificate_replicas.build_domain_list import BuildDomainList

# parser = BuildDomainList(
#     log_name = "sabre",
#     load_dir = r'D:/global_ca_monitor/data/group_top_domains_sabre',
#     save_dir = r'D:/global_ca_monitor/data/domain_list'
# )

parser = BuildDomainList()
parser.start()

while True:
    time.sleep(1)
