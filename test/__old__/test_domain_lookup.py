
import sys
sys.path.append(r"E:\global_ca_monitor")

import time
from backend.utils.domain_lookup import DomainLookup


start_time = time.time()

look_up = DomainLookup()
print(len(look_up.domain_set))
print(len(look_up.wildcard_dict.keys()))

end_time = time.time()
execution_time = end_time - start_time
print(f"1M set构建时间: {execution_time} 秒")

start_time = time.time()

target_domain = "g00gle.com"
# target_domain = "google.com"
# target_domain = "*.google.com"
print(look_up.lookup(target_domain))

end_time = time.time()
execution_time = end_time - start_time
print(f"1M set查询时间: {execution_time} 秒")
