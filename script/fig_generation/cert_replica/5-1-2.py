
from datetime import datetime
import json

# 比较相邻日期的 SAN 列表
def compare_san_lists(data):
    dates = sorted(data.keys())
    for i in range(1, len(dates)):
        prev_date = dates[i - 1]
        curr_date = dates[i]
        prev_san_list = set(data[prev_date][0])
        curr_san_list = set(data[curr_date][0])

        added_san = curr_san_list - prev_san_list
        removed_san = prev_san_list - curr_san_list

        print(f"从 {prev_date} 到 {curr_date} 的变化：")
        if added_san:
            try:
                print(f"  新增的 SAN 条目: {added_san}")
            except UnicodeEncodeError:
                print(f"  新增的 SAN 条目: {[item.encode() for item in added_san]}")

        if removed_san:
            try:
                print(f"  移除的 SAN 条目: {removed_san}")
            except UnicodeEncodeError:
                print(f"  移除的 SAN 条目: {[item.encode() for item in removed_san]}")

        if not added_san and not removed_san:
            print("  SAN 列表无变化")
        print()

with open('5-1-2.txt', 'r') as f:
    data = json.load(f)

    for domain, san_data in data.items():
        print(f"{domain}:\n")
        compare_san_lists(san_data)
