
import json

with open('5-2.txt', 'r') as f:
    data = json.load(f)

for domain, unique_lists in data.items():
    print(f"Domain: {domain}")

    if len(unique_lists) > 1:

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

