
import pandas as pd

# 读取 CSV 文件
df = pd.read_csv('related_domains_nimbus.csv')

# 定义拆分点，例如将前 50% 行存入第一个文件，剩余的行存入第二个文件
split_point = len(df) // 2

# 拆分为两个 DataFrame
df_part1 = df.iloc[:split_point]
df_part2 = df.iloc[split_point:]

# 将拆分的部分保存为两个 CSV 文件
df_part1.to_csv('related_domains_nimbus1.csv', index=False)
df_part2.to_csv('related_domains_nimbus2.csv', index=False)

print("CSV 文件已成功拆分为两个文件。")
