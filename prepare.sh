#!/bin/bash

# 激活虚拟环境（按需修改）
source ./myenv/bin/activate

# prepare all the python env
pip install -e .

# clear redis
redis-cli flushall

# start Celery Worker
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=200
