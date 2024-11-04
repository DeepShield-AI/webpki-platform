
import sys
sys.path.append(r"D:\global_ca_monitor")
from app.utils.network import *

print(resolve_host_dns())
print(resolve_host_dns(host="www.google.com"))
print(resolve_host_dns(host="www.baidu.cn"))
print(resolve_host_dns(host="www.tsinghua.edu.cn"))
print(resolve_host_dns(host="www.github.com"))
