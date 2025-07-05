
# db_pool.py
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import Engine
from backend.config.config_loader import DB_CONFIG

DB_CERT = "cert"
DB_CA = "ca"
DB_TLS = "tls"

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
engine_ca : Engine = make_engine(DB_CA)
engine_tls : Engine = make_engine(DB_TLS)
