
import sys
sys.path.append(r"/root/pki-internet-platform")

from app.utils.network import *

# print(resolve_host_dns())
# print(resolve_host_dns(host="www.google.com"))
# print(resolve_host_dns(host="www.baidu.cn"))
# print(resolve_host_dns(host="www.tsinghua.edu.cn"))
# print(resolve_host_dns(host="www.github.com"))


import dns.resolver

resolver = dns.resolver.Resolver()
resolver.nameservers = ['114.114.114.114']  # 使用指定的 DNS 服务器
try:
    result = resolver.resolve('zhaoban.ccom.edu.cn', 'A')  # 显式指定 A 记录
    for ip in result:
        print(ip)
except Exception as e:
    print(f"Error: {e}")
