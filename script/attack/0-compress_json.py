
import sys
sys.path.append(r"D:\global_ca_monitor")

import json
from backend.utils.json import custom_serializer

# 读取 JSON 文件并转化为符合要求的格式
def convert_json(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)  # 读取 JSON 文件

        # 使用 json.dumps 转换格式
        json_str = json.dumps(
            data,
            ensure_ascii=False,   # 确保非 ASCII 字符正常显示
            separators=(',', ':'),  # 移除逗号和冒号后面的空格，紧凑格式
            default=custom_serializer  # 自定义序列化器
        )

        # 将转换后的 JSON 字符串写回文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_str)

        print(f"文件已成功转换并保存为: {output_file}")

    except FileNotFoundError:
        print(f"找不到文件: {input_file}")
    except json.JSONDecodeError:
        print(f"无法解析 JSON 文件: {input_file}")
    except Exception as e:
        print(f"发生错误: {e}")

# 示例调用
input_file = 'related_domains_count_sabre'   # 输入文件路径
output_file = 'related_domains_count_sabre.json'  # 输出文件路径
convert_json(input_file, output_file)


# import sys
# import json
# sys.path.append(r"D:\global_ca_monitor")

# def convert_json(input_file):
#     with open(input_file, 'r', encoding='utf-8') as f:
#         data = json.load(f)  # 读取 JSON 文件
#         for i, v in data.items():
#             print(i, v)

# input_file = 'related_domains_count_sabre.json'  # 输出文件路径
# convert_json(input_file)
