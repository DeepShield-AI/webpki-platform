import socket

# 获取本地 IP 地址
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

print(f"本地 IP 地址: {local_ip}")
