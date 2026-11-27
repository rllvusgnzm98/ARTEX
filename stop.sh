#!/usr/bin/env bash
# ARTEX 停止脚本：仅停止当前目录下的 start.sh 守护进程与 artex 二进制，
# 避免误伤 postgres: artex worker 或路径中含 ARTEX/start.sh 的外层脚本。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd -P)"
cd "$DIR"

same_dir() {
  local pid="$1"
  if [ -d "/proc/$pid" ]; then
    local cwd
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    [ -z "$cwd" ] || [ "$cwd" = "$DIR" ]
  else
    return 0
  fi
}

SUP_PIDS=()
while read -r pid args; do
  [ -z "${pid:-}" ] && continue
  [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ] && continue
  if printf '%s\n' "$args" | grep -Eq '^(/(usr/)?bin/)?(ba|da|z)?sh[[:space:]]+(\./|'"$DIR"'/)?start\.sh([[:space:]]|$)'; then
    if same_dir "$pid"; then
      SUP_PIDS+=("$pid")
    fi
  fi
done < <(ps -eo pid=,args=)

BIN_PIDS=()
while read -r pid; do
  [ -z "${pid:-}" ] && continue
  [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ] && continue
  if same_dir "$pid"; then
    BIN_PIDS+=("$pid")
  fi
done < <(pgrep -x artex 2>/dev/null || true)

if [ "${#SUP_PIDS[@]}" -eq 0 ] && [ "${#BIN_PIDS[@]}" -eq 0 ]; then
  echo "[artex] 未运行"
  exit 0
fi

ALL_PIDS=("${SUP_PIDS[@]}" "${BIN_PIDS[@]}")
echo "[artex] 正在停止进程 (PID: ${ALL_PIDS[*]})..."

# 先停 start.sh 守护进程（它会转发 SIGTERM 给子进程并置 stopping=1，避免被自动拉起）
if [ "${#SUP_PIDS[@]}" -gt 0 ]; then
  kill -TERM "${SUP_PIDS[@]}" 2>/dev/null || true
fi
if [ "${#BIN_PIDS[@]}" -gt 0 ]; then
  kill -TERM "${BIN_PIDS[@]}" 2>/dev/null || true
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
  alive=0
  for pid in "${ALL_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      alive=1
      break
    fi
  done
  [ "$alive" -eq 0 ] && break
  sleep 0.5
done

echo "[artex] 已停止"
