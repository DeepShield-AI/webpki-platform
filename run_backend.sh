#!/bin/bash

source ./myenv/bin/activate

# config redis (max mem = 512M)
redis-cli flushall
redis-cli CONFIG SET maxmemory 536870912
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# config MySQL
mysql -u root -e "SET GLOBAL max_connections=205;"

# start Celery Worker 
# 2 processes, each for 50 threads, each thread run max 50 tasks and max process memory is 512M
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=50 --pool=threads --hostname=worker1@%h --max-tasks-per-child=50 --max-memory-per-child=512 &
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=50 --pool=threads --hostname=worker2@%h --max-tasks-per-child=50 --max-memory-per-child=512 &
celery -A backend.celery.celery_app:celery_app call backend.celery.celery_redis.flush_redis_queue
celery -A backend.celery.celery_app:celery_app beat --loglevel=info &
