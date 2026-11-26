#!/usr/bin/env bash
# ARTEX 停止脚本
set -e

cd "$(dirname "$0")"

PID=$(pgrep -f "artex" || true)
if [ -z "$PID" ]; then
  echo "[artex] 未运行"
  exit 0
fi

echo "[artex] 正在停止进程 (PID: $PID)..."
pkill -TERM -f "start.sh" 2>/dev/null || true
pkill -TERM -f "./artex" 2>/dev/null || true
sleep 1
echo "[artex] 已停止"
