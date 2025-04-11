
# config_loader.py
import os
from dotenv import load_dotenv

load_dotenv()

def get_bool(key: str, default=False):
    return os.getenv(key, str(default)).lower() == "true"

# 依赖工具
ZGRAB2_PATH = os.getenv("ZGRAB2_PATH", "/usr/bin/zgrab2")
ZMAP_PATH = os.getenv("ZMAP_PATH", "/usr/local/sbin/zmap")

# 默认线程设置
MAX_TASKS_PARALLEL = int(os.getenv("MAX_TASKS_PARALLEL", 100))
SINGLE_TASK_WORKLOAD = int(os.getenv("SINGLE_TASK_WORKLOAD", 2000))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", 5))
MAX_RETRY = int(os.getenv("MAX_RETRY", 3))
ENABLE_JARM = get_bool("ENABLE_JARM", False)

# 默认输入文件
INPUT_LIST_FILE = os.getenv("INPUT_LIST_FILE", "cisco-top-1m.csv")

# 默认文件输出地址
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "out/")

# IP 黑名单
DEFAULT_IP_BLACKLIST = [ip.strip() for ip in os.getenv("IP_BLACKLIST", "").split(",") if ip.strip()]

# proxy
PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("PROXY_PORT", 33210))

# 数据库配置
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "tianyu"),
    "password": os.getenv("DB_PASSWORD"),
    "charset": os.getenv("DB_CHARSET", "utf8mb4"),
    "port": int(os.getenv("DB_PORT", 3306))
}
