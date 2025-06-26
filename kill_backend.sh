#!/bin/bash

echo "Killing all Celery processes..."

# 获取所有 celery 相关的进程 PID（排除 grep 本身）
PIDS=$(ps aux | grep 'celery' | grep -v 'grep' | awk '{print $2}')

if [ -z "$PIDS" ]; then
    echo "✅ No Celery process found."
else
    echo "🔍 Found PIDs: $PIDS"
    kill $PIDS
    echo "✅ Celery processes killed."
fi
