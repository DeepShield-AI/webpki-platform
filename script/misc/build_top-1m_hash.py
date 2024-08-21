

from pybloom_live import BloomFilter

# 初始化布隆过滤器
bloom = BloomFilter(capacity=1000000, error_rate=0.001)

# 添加Top1M域名
for domain in top1m_domains:
    bloom.add(domain)

# 查询域名
def check_domain(domain):
    if domain in bloom:
        print(f"{domain} 可能存在")
    else:
        print(f"{domain} 不存在")

# 示例查询
check_domain('example.com')



# 假设 top_domains 是前 Top 1M 的域名
top_domains = set(["example.com", "sub.example.com", "..."])  # 使用 set 提高查找效率

def is_top_domain(domain):
    return domain in top_domains




class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_domain = False

class DomainTrie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, domain):
        node = self.root
        labels = domain.split('.')[::-1]  # 从 TLD 开始
        for label in labels:
            if label not in node.children:
                node.children[label] = TrieNode()
            node = node.children[label]
        node.is_end_of_domain = True

    def search(self, domain):
        node = self.root
        labels = domain.split('.')[::-1]  # 从 TLD 开始
        for label in labels:
            if label in node.children:
                node = node.children[label]
            elif '*' in node.children:  # 匹配通配符
                node = node.children['*']
            else:
                return False
        return node.is_end_of_domain

# 构建 Trie
domain_trie = DomainTrie()
for domain in top_1m_domains:
    domain_trie.insert(domain)

# 查找是否有匹配的域名
matching_certificates = []
for cert in certificates:
    if any(domain_trie.search(domain) for domain in cert.matchced_domain):
        matching_certificates.append(cert)
