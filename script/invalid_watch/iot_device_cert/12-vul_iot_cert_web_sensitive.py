
import ssl
import socket
import re

# 定义一些敏感关键字（可根据需要扩展）
SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "secret",
    "apikey", "access_token", "privatekey",
    "ssn", "creditcard", "身份证", "账号", "密码"
]

def fetch_tls_page(ip, port=443, timeout=5):
    """
    尝试通过 TLS 连接获取返回内容 (忽略证书验证)
    """
    # 创建默认 SSL 上下文
    context = ssl.create_default_context()
    # 禁用证书验证
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip.strip(), port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip.strip()) as ssock:
                # 发送最简单的 HTTP 请求
                request = f"GET / HTTP/1.1\r\nHost: {ip.strip()}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode("utf-8"))

                # 循环读取完整响应（避免只拿到一小部分）
                response_chunks = []
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)

                return b"".join(response_chunks).decode(errors="ignore")

    except Exception as e:
        return f"[ERROR] {ip.strip()}: {e}"

def contains_sensitive_data(text):
    """
    简单关键字匹配，判断是否包含敏感数据
    """
    findings = []
    for keyword in SENSITIVE_KEYWORDS:
        if re.search(keyword, text, re.IGNORECASE):
            findings.append(keyword)
    return findings

if __name__ == "__main__":
    with open("13-vul_ip.txt", "r") as f:
        for ip in f:
            ip = ip.strip()
            if not ip:
                continue

            print(f"[*] Checking {ip}:443 ...")
            page_data = fetch_tls_page(ip)

            if page_data.startswith("[ERROR]"):
                print(page_data)
                continue

            hits = contains_sensitive_data(page_data)
            if hits:
                print(f"[!] Sensitive keywords found in {ip}: {hits}")
            else:
                print(f"[-] No sensitive data detected on {ip}")
