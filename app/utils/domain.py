
import tldextract
from collections import defaultdict

def group_by_root_domain(domains):

    root_domains = set()
    for domain in domains:
        # 使用 tldextract 提取根域名（主域名 + TLD）
        ext = tldextract.extract(domain)
        root_domain = f"{ext.domain}.{ext.suffix}"
        root_domains.add(root_domain)
    
    return root_domains
