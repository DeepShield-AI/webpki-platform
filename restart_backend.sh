#!/bin/bash
# 重启 celery worker 进程

echo "$(date): Restarting Celery workers" >> /var/log/celery_restart.log
supervisorctl restart celery_worker1
supervisorctl restart celery_worker2
