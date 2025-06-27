#!/bin/bash

source ./myenv/bin/activate

# clear redis
redis-cli flushall

# start Celery Worker 
# 2 processes, each for 50 threads
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=50 --pool=threads --hostname=worker1@%h &
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=50 --pool=threads --hostname=worker2@%h &
celery -A backend.celery.celery_app:celery_app call backend.celery.celery_redis.flush_redis_queue
celery -A backend.celery.celery_app:celery_app beat --loglevel=info &
