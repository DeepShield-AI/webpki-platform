
'''
    2 - Certificate Policies
    (1) 总体上证书使用的 Policy 状态如何？
    (2) 在同一天的证书的使用情况
    (3) 相同的 SAN 中使用 的 情况
'''

import numpy as np
import matplotlib.pyplot as plt
import json
import csv
import os
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from datetime import datetime
import base64
import ast

# 自定义序列化函数
def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d")
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
    raise TypeError(f"Type {type(obj)} not serializable")

# 读取 Certificate policy
policy_dict = {}
with open(os.path.join(os.path.dirname(__file__), r"../../../app/data/certificate_policies.csv"), 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:

        dv = row[6]
        ov = row[7]
        ev = row[8]
        iv = row[9]

        if dv == "TRUE" and ov == "TRUE":
            policy_dict[row[0]] = "dov"
        elif dv == "TRUE":
            policy_dict[row[0]] = "dv"
        elif ov == "TRUE":
            policy_dict[row[0]] = "ov"
        elif ev == "TRUE":
            policy_dict[row[0]] = "ev"
        elif iv == "TRUE":
            policy_dict[row[0]] = "iv"
        else:
            policy_dict[row[0]] = "Unknown"

# 读取 JSON 数据
with open(r'H:/cert_replica/counting_out_50M.json', 'r') as f:
    json_data = json.load(f)

    _1_policy_overview = {}
    _2_policy_for_same_day = {}
    _3_policy_for_same_san = {}

    for domain, data in json_data.items():
        if data["num"] > 1:

            _1_policy_overview[domain] = data["cert_type"]
            _2_policy_for_same_day[domain] = {}
            _3_policy_for_same_san[domain] = {}

            not_before_to_everything = data['not_before_to_everything']
            subject_set_to_everything = data['subject_set_to_everything']

            # time
            for not_before, certs in not_before_to_everything.items():
                _2_policy_for_same_day[domain][not_before] = certs["cert_type"]

            # san
            for san_set, certs in subject_set_to_everything.items():
                _3_policy_for_same_san[domain][san_set] = certs["cert_type"]


with open("2-1.txt", "w") as file:
    json.dump(_1_policy_overview, file, indent=4, default=custom_serializer)

with open("2-2.txt", "w") as file:
    json.dump(_2_policy_for_same_day, file, indent=4, default=custom_serializer)

with open("2-3.txt", "w") as file:
    json.dump(_3_policy_for_same_san, file, indent=4, default=custom_serializer)

# _1_
more_than_one_policies = {}
for domain, data in _1_policy_overview.items():

    if len(data.keys()) > 1:
        more_than_one_policies[domain] = {}

        for policy_oid, num in data.items():
            try:
                policy = policy_dict[policy_oid]
            except KeyError:
                policy = "Unknown"
            if policy not in more_than_one_policies[domain]:
                more_than_one_policies[domain][policy] = 0
            more_than_one_policies[domain][policy] += 1

with open("2-1-1.txt", "w") as file:
    json.dump(more_than_one_policies, file, indent=4, default=custom_serializer)

# _2_
more_than_one_policies = {}
for domain, data in _2_policy_for_same_day.items():

    for date, policies in data.items():
        if len(set(policies)) > 1:
            if date not in more_than_one_policies:
                more_than_one_policies[date] = []
            unique_list = list(set(policies))
            more_than_one_policies[date].append({
                "domain" : domain,
                "policies" : [policy_dict[p] for p in unique_list]
            })

with open("2-2-1.txt", "w") as file:
    json.dump(more_than_one_policies, file, indent=4, default=custom_serializer)

# _3_
more_than_one_policies = {}
for domain, data in _3_policy_for_same_san.items():

    for san, policies in data.items():
        if len(set(policies)) > 1:
            if san not in more_than_one_policies:
                more_than_one_policies[san] = []
            unique_list = list(set(policies))
            more_than_one_policies[san].append({
                "domain" : domain,
                "policies" : [policy_dict[p] for p in unique_list]
            })

with open("2-3-1.txt", "w") as file:
    json.dump(more_than_one_policies, file, indent=4, default=custom_serializer)


# # CDF
# sorted_y = np.sort(change_ca_times)

# # 计算 CDF y 值
# cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

# # 绘制 CDF 曲线图
# plt.plot(sorted_y, cdf_y, color='b', label='CDF', marker='o')
# plt.title('CDF of Change CA Times')
# plt.xlabel('Value')
# plt.ylabel('CDF')
# plt.legend()

# plt.savefig('4-1.png', dpi=300, bbox_inches='tight')
# plt.show()

