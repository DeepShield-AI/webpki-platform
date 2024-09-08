
import json
import numpy as np
import matplotlib.pyplot as plt

with open('5-1-3.txt', 'r') as f:
    data = json.load(f)


domain_template_num_counting = {}
domain_template_num_counting_groups = {}
for domain, dates in data.items():
    # print(f"Domain: {domain}")
    domain_template_num_counting[domain] = set()
    domain_template_num_counting_groups[domain] = {}

    for date, lists in dates.items():
        # print(f" Date: {date}")

        for lst in lists:
            domain_template_num_counting[domain].add(str(lst))

            if tuple(lst) not in domain_template_num_counting_groups[domain]:
                domain_template_num_counting_groups[domain][tuple(lst)] = 0
            domain_template_num_counting_groups[domain][tuple(lst)] += 1

        # # 去重
        # print(lists)
        # unique_lists = [list(set(lst)) for lst in lists]
        # unique_lists = [sorted(lst) for lst in unique_lists]  # 排序以确保一致性
        # unique_lists = [list(t) for t in set(tuple(l) for l in unique_lists)]  # 去重

        # # 比较每个日期中的所有唯一列表
        # num_lists = len(unique_lists)

        # diff_set = []
        # for i in range(num_lists):
        #     for j in range(i + 1, num_lists):
        #         list1 = set(unique_lists[i])
        #         list2 = set(unique_lists[j])
                
        #         # 计算差异
        #         diff1_to_2 = list1 - list2
        #         diff2_to_1 = list2 - list1
        #         intersection = list1 & list2

        #         diff_set += diff1_to_2
        #         diff_set += diff2_to_1
        
        # diff_set = set(diff_set)
        # try:
        #     print(diff_set)
        # except:
        #     print(set([i.encode() for i in diff_set]))
    
    if len(domain_template_num_counting[domain]) > 3:
        print(f"Domain: {domain}")
        print(f"SAN Templates: {domain_template_num_counting[domain]}")

        # 获取所有可能的序列元素并创建映射
        all_elements = set([item for sequence in domain_template_num_counting_groups[domain].keys() for item in sequence])
        element_mapping = {element: i for i, element in enumerate(sorted(all_elements))}

        # 提取x, y, z坐标和计数
        x = []
        y = []
        z = []
        counts = []

        for sequence, count in domain_template_num_counting_groups[domain].items():
            mapped_sequence = [element_mapping[element] for element in sequence]
            
            # 如果序列长度不足3，补齐为0（或你选择的填充值）
            while len(mapped_sequence) < 3:
                mapped_sequence.append(0)
            
            x.append(mapped_sequence[0])
            y.append(mapped_sequence[1])
            z.append(mapped_sequence[2])
            counts.append(count)

        # 创建3D散点图
        fig = plt.figure(figsize=(10, 7))
        ax = fig.add_subplot(111, projection='3d')

        # 根据计数大小设置点的大小
        sizes = [c * 200 for c in counts]

        scatter = ax.scatter(x, y, z, s=sizes, c=counts, cmap='viridis', alpha=0.6)

        # 添加颜色条
        fig.colorbar(scatter, ax=ax, label='Count')

        # 设置坐标轴标签
        ax.set_xlabel('X Axis')
        ax.set_ylabel('Y Axis')
        ax.set_zlabel('Z Axis')
        ax.set_title('3D Scatter Plot of Sequence Group Sizes')

        # 设置x轴、y轴和z轴的tick间距
        ax.set_xticks(range(min(x), max(x) + 1, 1))
        ax.set_yticks(range(min(y), max(y) + 1, 1))
        ax.set_zticks(range(min(z), max(z) + 1, 1))
        plt.show()

        # # 获取所有可能的序列元素并创建映射
        # all_elements = set([item for sequence in domain_template_num_counting_groups[domain].keys() for item in sequence])
        # element_mapping = {element: i for i, element in enumerate(sorted(all_elements))}

        # # 提取x, y坐标和计数
        # x = []
        # y = []
        # counts = []

        # for sequence, count in domain_template_num_counting_groups[domain].items():
        #     mapped_sequence = [element_mapping[element] for element in sequence]
            
        #     # 如果序列长度不足2，补齐为0（或你选择的填充值）
        #     while len(mapped_sequence) < 2:
        #         mapped_sequence.append(0)
            
        #     x.append(mapped_sequence[0])
        #     y.append(mapped_sequence[1])
        #     counts.append(count)

        # # 创建2D散点图
        # plt.figure(figsize=(10, 7))

        # # 根据计数大小设置点的大小
        # sizes = [c * 50 for c in counts]

        # plt.scatter(x, y, s=sizes, c=sizes, cmap='viridis', alpha=0.6)

        # # 添加颜色条
        # plt.colorbar(label='Count')

        # # 设置坐标轴标签
        # plt.xlabel('Element 1')
        # plt.ylabel('Element 2')
        # plt.title('2D Scatter Plot of Sequence Group Sizes')

        # plt.show()


# cdf
template_counting = [len(_set) for _set in domain_template_num_counting.values()]
sorted_y = np.sort(template_counting)

# 计算 CDF y 值
cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# 绘制 CDF 曲线图
plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
plt.title('CDF of SAN Templates')
plt.xlabel('Value')
plt.ylabel('CDF')
plt.legend()

plt.savefig('5-1-3-1.png', dpi=300, bbox_inches='tight')
plt.show()

