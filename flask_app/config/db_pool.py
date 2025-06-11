
# db_pool.py
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import Engine

import os
from dotenv import load_dotenv
load_dotenv()  # 默认会加载 .env 文件

# 数据库配置
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "tianyu"),
    "password": os.getenv("DB_PASSWORD", "123456"),
    "charset": os.getenv("DB_CHARSET", "utf8mb4"),
    "port": int(os.getenv("DB_PORT", 3306))
}

DB_CERT = "cert"
DB_TLS = "tls_handshake"

def make_engine(db_name):

    db_url = "mysql+pymysql://{user}:{password}@{host}:{port}/{db_name}?charset={charset}".format(
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        db_name=db_name,
        charset=DB_CONFIG["charset"]
    )

    return create_engine(
        db_url,
        poolclass=QueuePool,
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,
        echo=False  # 打印 SQL 用于调试
    )

engine_cert : Engine = make_engine(DB_CERT)
engine_tls : Engine = make_engine(DB_TLS)
