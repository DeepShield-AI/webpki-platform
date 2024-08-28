
import json

with open('5-1-3.txt', 'r') as f:
    data = json.load(f)

for domain, dates in data.items():
    print(f"Domain: {domain}")
    for date, lists in dates.items():
        print(f" Date: {date}")

        # 去重
        unique_lists = [list(set(lst)) for lst in lists]
        unique_lists = [sorted(lst) for lst in unique_lists]  # 排序以确保一致性
        unique_lists = [list(t) for t in set(tuple(l) for l in unique_lists)]  # 去重

        # 比较每个日期中的所有唯一列表
        num_lists = len(unique_lists)

        diff_set = []
        for i in range(num_lists):
            for j in range(i + 1, num_lists):
                list1 = set(unique_lists[i])
                list2 = set(unique_lists[j])
                
                # 计算差异
                diff1_to_2 = list1 - list2
                diff2_to_1 = list2 - list1
                intersection = list1 & list2

                diff_set += diff1_to_2
                diff_set += diff2_to_1
        
        diff_set = set(diff_set)
        try:
            print(diff_set)
        except:
            print(set([i.encode() for i in diff_set]))
