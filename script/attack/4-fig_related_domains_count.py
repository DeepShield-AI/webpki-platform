
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# 读取CSV文件
df = pd.read_csv('related_domains_count_sabre.csv')
# df = pd.read_csv('related_domains_count_nimbus.csv')

# 将每100个数据进行聚合
bin_size = 100
df['Bin'] = df.index // bin_size  # 创建bin列，按每100个数据分组

# 按照每100个数据计算总数
df_aggregated = df.groupby('Bin').agg({'Value': 'sum'}).reset_index()

# 设置全局矩阵大小，100万条数据每100个分一组，得到10000个组
num_bins = len(df_aggregated)
global_rows, global_cols = 10, 10  # 外层 10x10 大格子
inner_rows, inner_cols = 10, 10  # 每个格子内部 10x10

# 初始化全局矩阵
matrix = np.zeros((global_rows * inner_rows, global_cols * inner_cols))

# 填充矩阵
for i, row in df_aggregated.iterrows():
    if i >= global_rows * global_cols * inner_rows * inner_cols:  # 确保不超过矩阵大小
        break
    outer_row = (i // (global_rows * global_cols)) // inner_rows  # 外层行索引
    outer_col = (i // (global_rows * global_cols)) % global_cols  # 外层列索引
    inner_index = i % (global_rows * global_cols)  # 当前块中的索引
    inner_row = inner_index // inner_cols  # 内层行索引
    inner_col = inner_index % inner_cols  # 内层列索引

    # 定位具体到每个小格子的位置
    value = row['Value']
    if value > 0:
        matrix[outer_row * inner_rows + inner_row, outer_col * inner_cols + inner_col] += np.log(value)  # 使用对数映射非0值
    else:
        matrix[outer_row * inner_rows + inner_row, outer_col * inner_cols + inner_col] = np.nan  # 0 用 NaN 表示

# 计算颜色映射的上下限
vmin = 0 # 最小值
vmax = 15  # 最大值

# 绘制热图
plt.figure(figsize=(6, 6))
ax = sns.heatmap(matrix, cmap='YlGnBu', mask=np.isnan(matrix), square=True,
                 cbar_kws={"shrink": 0.5, "aspect": 10}, vmin=vmin, vmax=vmax)  # 设置上下限

# 去掉热图的默认网格线
ax.xaxis.grid(False)
ax.yaxis.grid(False)

# 设置 x 和 y 轴的刻度
ax.set_xticks(np.arange(0, matrix.shape[1], inner_cols))
ax.set_yticks(np.arange(0, matrix.shape[0], inner_rows))

# 添加外层 10x10 大格子的网格线
for i in range(0, matrix.shape[0], inner_rows):
    ax.axhline(i, color='black', linewidth=1.5)

for j in range(0, matrix.shape[1], inner_cols):
    ax.axvline(j, color='black', linewidth=1.5)

# 去掉标题
plt.xlabel('Binned Rank Index')
plt.ylabel('Binned Rank Group')
plt.savefig("related_domain_count_sabre.png")
# plt.savefig("related_domain_count_nimbus.png")
