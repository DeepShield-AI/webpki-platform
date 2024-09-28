
import base64
from datetime import datetime

# 自定义序列化函数
def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()  # 或者用 obj.strftime("%Y-%m-%d %H:%M:%S") 等其他格式
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
    if isinstance(obj, bytearray):
        return base64.b64encode(obj).decode('utf-8')
    raise TypeError(f"Type {type(obj)} not serializable")

# Split json objects from a single file with mulitiple json objs
def split_json_objects(data):
    json_objects = []
    brace_count = 0
    json_str = ""

    for char in data:
        json_str += char

        # 计算花括号的数量来判断 JSON 对象是否完整
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1

        # 当 brace_count 为 0 时，说明一个 JSON 对象已完整
        if brace_count == 0 and json_str.strip():
            json_objects.append(json_str.strip())
            json_str = ""

    return json_objects
