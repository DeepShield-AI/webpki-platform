
import re
import ipaddress
import tldextract

def group_by_root_domain(domains):

    root_domains = set()
    for domain in domains:
        # 使用 tldextract 提取根域名（主域名 + TLD）
        ext = tldextract.extract(domain)
        root_domain = f"{ext.domain}.{ext.suffix}"
        root_domains.add(root_domain)
    
    return root_domains

def check_input_type(s):
    try:
        ipaddress.ip_address(s)
        return 'IP address'
    except ValueError:
        # 支持可选的通配符前缀 *.example.com
        domain_regex = r"^(?:\*\.)?(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
        if re.match(domain_regex, s):
            return 'Domain'
        else:
            return 'Invalid'
        