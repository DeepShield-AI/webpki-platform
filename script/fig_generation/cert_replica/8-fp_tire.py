from collections import defaultdict

# Tier节点结构
class TierNode:
    def __init__(self):
        self.children = {}
        self.count = 0

# 构建Tier
class Tier:
    def __init__(self):
        self.root = TierNode()

    def insert(self, domain_parts):
        node = self.root
        for part in domain_parts:
            if part not in node.children:
                node.children[part] = TierNode()
            node = node.children[part]
            node.count += 1

    def traverse(self):
        # DFS遍历Tier，输出路径
        stack = [(self.root, [])]
        while stack:
            node, path = stack.pop()
            for part, child in node.children.items():
                new_path = path + [part]
                yield new_path, child.count
                stack.append((child, new_path))

# FP-Growth整合
def fpgrowth_with_tier(tier, min_support):
    patterns = defaultdict(int)

    # 在Tier中递归挖掘频繁模式
    def find_patterns(node, path):
        for part, child in node.children.items():
            new_path = path + [part]
            if child.count >= min_support:
                patterns[tuple(new_path)] = child.count
                find_patterns(child, new_path)

    find_patterns(tier.root, [])
    return patterns

# 示例数据集
domains = [
    "00xzu8-226-ppp.oss-accelerate.aliyuncs.com",
    "*.oss-cn-hongkong-internal.aliyuncs.com",
    "*.oss.aliyuncs.com",
    "*.aliyuncs.com"
]

# 构建Tier并插入域名
tier = Tier()
for domain in domains:
    domain_parts = domain.split('.')[::-1]  # 逆序插入，使得根域名在Tier的顶部
    tier.insert(domain_parts)

# 最小支持度设定
min_support = 2

# 运行FP-Growth结合Tier
patterns = fpgrowth_with_tier(tier, min_support)

# 输出结果
for pattern, support in patterns.items():
    print(f"Pattern: {'.'.join(pattern[::-1])}, Support: {support}")
