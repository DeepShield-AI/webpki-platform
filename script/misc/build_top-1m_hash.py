

# from pybloom_live import BloomFilter

# # 初始化布隆过滤器
# bloom = BloomFilter(capacity=1000000, error_rate=0.001)

# # 添加Top1M域名
# for domain in top1m_domains:
#     bloom.add(domain)

# # 查询域名
# def check_domain(domain):
#     if domain in bloom:
#         print(f"{domain} 可能存在")
#     else:
#         print(f"{domain} 不存在")

# # 示例查询
# check_domain('example.com')


# def is_top_domain(domain):
#     return domain in top_domains
