#!/bin/bash

source ./myenv/bin/activate

# clear redis
redis-cli flushall

# start Celery Worker
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=20 &
celery -A backend.celery.celery_app:celery_app call backend.celery.celery_redis.flush_redis_queue
celery -A backend.celery.celery_app:celery_app beat --loglevel=info &
