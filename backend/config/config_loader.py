
# config_loader.py
import os
from dotenv import load_dotenv

load_dotenv()

ZGRAB2_PATH = os.getenv("ZGRAB2_PATH", "/usr/bin/zgrab2")
ZMAP_PATH = os.getenv("ZMAP_PATH", "/usr/local/sbin/zmap")

# 默认线程设置
MAX_THREADS_ALLOC = int(os.getenv("MAX_THREADS_ALLOC", 100))
THREAD_WORKLOAD = int(os.getenv("THREAD_WORKLOAD", 2000))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", 5))
MAX_RETRY = int(os.getenv("MAX_RETRY", 3))

# 默认输入文件
DEFAULT_DOMAIN_LIST_FILE = os.getenv("INPUT_DOMAIN_LIST_FILE")
DEFAULT_IP_LIST_FILE = os.getenv("INPUT_IP_LIST_FILE")
DEFAULT_STORAGE_DIR = os.getenv("STORAGE_DIR")

# IP 黑名单
IP_BLACKLIST = [ip.strip() for ip in os.getenv("IP_BLACKLIST", "").split(",") if ip.strip()]
