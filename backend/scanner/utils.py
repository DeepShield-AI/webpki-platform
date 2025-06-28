
import json
import redis
import pprint

r = redis.Redis()

# Redis 只能存储字符串或字节
def enqueue_scan_result(result: dict):
    # pprint.pprint(result)
    r.rpush("scan_results_queue", json.dumps(result))
