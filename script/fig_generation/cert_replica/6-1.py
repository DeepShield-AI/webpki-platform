
import json

with open('6-1.txt', 'r') as f:
    domain_data = json.load(f)

# 初始化密钥的使用次数字典
key_reuse_domains = set()

# 遍历所有域名和其公钥
for domain, data in domain_data.items():
    for key, num in data['pub_key'].items():
        if num > 1:
            key_reuse_domains.add(domain)

with open("6-1-1.txt", "w") as file:
    json.dump(list(key_reuse_domains), file, indent=4)
