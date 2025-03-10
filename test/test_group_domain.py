import tldextract
from collections import defaultdict

def group_by_root_domain(domains):
    # 创建一个字典来保存分组结果
    groups = defaultdict(list)
    
    # 遍历域名列表
    for domain in domains:
        # 使用 tldextract 提取根域名（主域名 + TLD）
        ext = tldextract.extract(domain)
        root_domain = f"{ext.domain}.{ext.suffix}"
        
        # 将域名分配到对应的根域名组中
        groups[root_domain].append(domain)
    
    return dict(groups)

# 示例域名列表
domains = [
    "*.jpmorgan.com",
    "tssportal.jpmorgan.com", "access.jpmorgan.com", "access.jpmacontent.com", 
    "accesspsaas.jpmacontent.com", "accesspsaas.jpmorgan.com", "accesswl.acctmanagement.com", 
    "accesswlpsaas.acctmanagement.com", "cdn.access.jpmorgan.com", "cdn.accesspsaas.jpmorgan.com", 
    "cdnpsaas.access.jpmorgan.com", "dashboard.jpmorgan.com", "dashboardpsaas.jpmorgan.com", 
    "jpmorganaccess.com", "srvc1.jpmorgan.com", "srvc1psaas.jpmorgan.com", "srvc2.jpmorgan.com", 
    "srvc2psaas.jpmorgan.com", "srvc3.jpmorgan.com", "srvc3psaas.jpmorgan.com", 
    "srvcwl1.acctmanagement.com", "srvcwl1psaas.acctmanagement.com", "srvcwl2.acctmanagement.com", 
    "srvcwl2psaas.acctmanagement.com", "srvcwl3.acctmanagement.com", "srvcwl3psaas.acctmanagement.com", 
    "swedbank-custodyconnect.acctmanagement.com", "swedbank-custodyconnectpsaas.acctmanagement.com", 
    "tssportalpsaas.jpmorgan.com", "www.jpmorganaccess.com"
]

# 调用分组函数
grouped_domains = group_by_root_domain(domains)

# 输出结果
for root_domain, group in grouped_domains.items():
    print(f"Group for {root_domain}:")
    for domain in group:
        print(f"  - {domain}")
