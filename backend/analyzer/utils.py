
import json
import redis
import hashlib
import base64
from datetime import datetime
from collections import OrderedDict

from backend.config.analyze_config import AnalyzeConfig
from backend.celery.celery_app import celery_app
from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.logger.logger import primary_logger
from backend.parser.pem_parser import PEMParser
from backend.utils.exception import *
from backend.utils.type import sort_dict_by_key, sort_list_by_key
from backend.utils.json import custom_serializer

r = redis.Redis()
# r.expire("analyze_results_queue", 1 * 24 * 3600)  # 1 天过期

# Redis 只能存储字符串或字节
def enqueue_result(result: dict):
    r.rpush("analyze_results_queue", json.dumps(result, default=custom_serializer))

# go through the tls_handshake table
def stream_by_id(conn, table_name, batch_size=1000, start_id=0):

    # conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    last_id = start_id
    while True:
        if last_id:
            query = f"""
                SELECT * FROM {table_name}
                WHERE id > %s
                ORDER BY id ASC
                LIMIT %s
            """
            cursor.execute(query, (last_id, batch_size))
        else:
            query = f"""
                SELECT * FROM {table_name}
                ORDER BY id ASC
                LIMIT %s
            """
            cursor.execute(query, (batch_size,))
        rows = cursor.fetchall()
        if not rows:
            break
        yield from rows # this asyc make sure the read does not cause too much memory
        last_id = rows[-1][0]
    cursor.close()

# go through the cert table
def stream_by_sha256(table_name, batch_size=1000, start_hash=""):

    conn = engine_cert.raw_connection()
    cursor = conn.cursor()
    last_hash = start_hash
    while True:
        if last_hash:
            query = f"""
                SELECT * FROM {table_name}
                WHERE sha256 > %s
                ORDER BY sha256 ASC
                LIMIT %s
            """
            cursor.execute(query, (last_hash, batch_size))
        else:
            query = f"""
                SELECT * FROM {table_name}
                ORDER BY sha256 ASC
                LIMIT %s
            """
            cursor.execute(query, (batch_size,))
        rows = cursor.fetchall()
        if not rows:
            break
        yield from rows # this asyc make sure the read does not cause too much memory
        last_hash = rows[-1][0]  # 假设 sha256 是第一列
    cursor.close()
