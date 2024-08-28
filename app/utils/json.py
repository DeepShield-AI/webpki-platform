
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
    raise TypeError(f"Type {type(obj)} not serializable")
