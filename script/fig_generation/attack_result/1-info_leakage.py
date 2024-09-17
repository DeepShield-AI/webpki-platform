
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import base64
import json
import csv
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

# 读取排名数据
rank_dict = {}
with open(r"D:/global_ca_monitor/app/data/top-1m.csv", 'r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        rank_dict[row[1]] = row[0]

# 读取 JSON 数据
with open(r'H:/cert_replica/counting_out_50M.json', 'r') as f:
    json_data = json.load(f)

    _1_1_san_num_sort_by_not_before = {}
    _1_2_san_content_sort_by_not_before = {}
    _1_3_san_template_for_each_day = {}
    _2_all_san_instances = {}
    _3_domain_across_multiple_domains = {}

    for domain, data in json_data.items():
        if data["num"] > 1:

            _1_1_san_num_sort_by_not_before[domain] = {}
            _1_2_san_content_sort_by_not_before[domain] = {}
            _1_3_san_template_for_each_day[domain] = {}
            _2_all_san_instances[domain] = []
            _3_domain_across_multiple_domains[domain] = []

            not_before_to_everything = data['not_before_to_everything']
            subject_set_to_everything = data['subject_set_to_everything']

            # time
            for not_before, certs in not_before_to_everything.items():
                not_before_in_datetime = datetime.strptime(not_before, "%Y-%m-%d")

                total_subject_list_for_each_day = []
                _1_2_san_content_sort_by_not_before[domain][not_before] = []
                _1_3_san_template_for_each_day[domain][not_before] = []
                for subject_list in certs["subject_list"]:
                    total_subject_list_for_each_day += subject_list
                    _1_2_san_content_sort_by_not_before[domain][not_before].append(subject_list)

                total_subject_list_for_each_day = set(total_subject_list_for_each_day)
                _1_1_san_num_sort_by_not_before[domain][not_before] = len(total_subject_list_for_each_day)
                _1_3_san_template_for_each_day[domain][not_before] += certs["san_template"]

            _1_1_san_num_sort_by_not_before[domain] = dict(sorted(_1_1_san_num_sort_by_not_before[domain].items(), key=lambda item: item[0]))
            _1_2_san_content_sort_by_not_before[domain] = dict(sorted(_1_2_san_content_sort_by_not_before[domain].items(), key=lambda item: item[0]))
            _1_3_san_template_for_each_day[domain] = dict(sorted(_1_3_san_template_for_each_day[domain].items(), key=lambda item: item[0]))

            # san
            all_subjects = []
            for san_set, certs in subject_set_to_everything.items():
                subject_list = ast.literal_eval(san_set)
                all_subjects += subject_list
                _2_all_san_instances[domain].append(subject_list)
            _3_domain_across_multiple_domains[domain] = list(set(all_subjects))

with open("5-1-1.txt", "w") as file:
    json.dump(_1_1_san_num_sort_by_not_before, file, indent=4, default=custom_serializer)

with open("5-1-2.txt", "w") as file:
    json.dump(_1_2_san_content_sort_by_not_before, file, indent=4, default=custom_serializer)

with open("5-1-3.txt", "w") as file:
    json.dump(_1_3_san_template_for_each_day, file, indent=4, default=custom_serializer)

with open("5-2.txt", "w") as file:
    json.dump(_2_all_san_instances, file, indent=4, default=custom_serializer)

with open("5-3.txt", "w") as file:
    json.dump(_3_domain_across_multiple_domains, file, indent=4, default=custom_serializer)

