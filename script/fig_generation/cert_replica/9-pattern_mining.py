from pymining import seqmining

# 示例数据
data = [
    ["*.api-100.moengage.com", "*.az-prod-centralindia-c1.moengage.com", "*.az-staging-east-us-c1.moengage.com", "*.az-staging-eastus-c1.moengage.com", "*.az-staging-sre-c1.moengage.com", "*.moengage.com", "*.sdk-100.moengage.com"],
    ["*.az-staging-eastus-c1.moengage.com", "*.az100.moestaging.com", "*.moeinternal.com", "*.moengage.com", "*.moestaging.com"],
    ["*.az-prod-centralindia-c1.moengage.com", "*.moeinternal.com", "*.moengage.com"],
    ["*.az-staging-east-us-c1.moengage.com", "*.az-staging-eastus-c1.moengage.com", "*.az100.moestaging.com", "*.moeinternal.com", "*.moengage.com", "*.moestaging.com"]
]

# 设置最小支持度和最小序列长度
min_support = 0.5  # 50%
min_length = 2

# 使用 SPADE 挖掘序列模式
patterns = seqmining.spade(data, min_support=min_support, min_length=min_length)

# 打印结果
print("SPADE Patterns:")
for pattern in patterns:
    print(pattern)
