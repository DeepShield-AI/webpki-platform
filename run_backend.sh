#!/bin/bash

source ./myenv/bin/activate

# clear redis
redis-cli flushall

# start Celery Worker
celery -A backend.celery.celery_app:celery_app worker --loglevel=info --concurrency=5
