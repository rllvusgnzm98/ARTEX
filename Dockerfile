# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
# 构建源默认全空 = 官方源。镜像不可达时自动回退（apt 还原 sources 后再重试；
# npm / Playwright 是 if ! 镜像安装; then 官方安装; fi）：
#   docker build -t artex:local --build-arg APT_MIRROR=mirrors.aliyun.com .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 构建源（默认全空 = 官方源）。
# APT_MIRROR 只写主机名，例如 mirrors.aliyun.com，不要带协议。
# NODE_MAJOR 留空仍安装官方 Node 20（bookworm 自带的 nodejs 是 18，Playwright 要求 >=20）。
# NODESOURCE_URL / NPM_REGISTRY / PLAYWRIGHT_DOWNLOAD_HOST 留空 = 各自的官方地址。
ARG APT_MIRROR=
ARG NODE_MAJOR=
ARG NODESOURCE_URL=
ARG NPM_REGISTRY=
ARG PLAYWRIGHT_DOWNLOAD_HOST=
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# apt 改源前备份 sources.list 与 debian.sources；update 失败则 cp 回原文件，
# 再用 apt-get -o Acquire::Retries=3 继续。bookworm slim 实际用的是 debian.sources。
# Docker 会展开 ARG（${NODE_MAJOR:-20}、${APT_MIRROR} 等）。shell 自己的变量写成 $$。
RUN set -eu; \
    node_major="${NODE_MAJOR:-20}"; \
    if [ -f /etc/apt/sources.list ]; then cp /etc/apt/sources.list /tmp/sources.list.bak; fi; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then cp /etc/apt/sources.list.d/debian.sources /tmp/debian.sources.bak; fi; \
    if [ -n "$APT_MIRROR" ]; then \
      if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g; s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
      fi; \
      if [ -f /etc/apt/sources.list ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g; s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list; \
      fi; \
    fi; \
    if ! apt-get update; then \
      echo "apt mirror unreachable, restoring official sources"; \
      if [ -f /tmp/sources.list.bak ]; then cp /tmp/sources.list.bak /etc/apt/sources.list; fi; \
      if [ -f /tmp/debian.sources.bak ]; then cp /tmp/debian.sources.bak /etc/apt/sources.list.d/debian.sources; fi; \
      apt-get -o Acquire::Retries=3 update; \
    fi; \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
      ca-certificates bash ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap; \
    if [ -n "$NODESOURCE_URL" ]; then \
      if ! curl -fsSL "${NODESOURCE_URL}/setup_$${node_major}.x" -o /tmp/nodesource-setup.sh; then \
        curl -fsSL "https://deb.nodesource.com/setup_$${node_major}.x" -o /tmp/nodesource-setup.sh; \
      fi; \
    else \
      curl -fsSL "https://deb.nodesource.com/setup_$${node_major}.x" -o /tmp/nodesource-setup.sh; \
    fi; \
    bash /tmp/nodesource-setup.sh; \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/* /tmp/nodesource-setup.sh
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
# NPM_REGISTRY / PLAYWRIGHT_DOWNLOAD_HOST 非空时先走镜像，失败再官方安装。
RUN set -eu; \
    if [ -n "$NPM_REGISTRY" ]; then \
      if ! npm install -g --registry="$NPM_REGISTRY" @playwright/mcp@latest @playwright/cli@latest playwright@latest; then \
        npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest; \
      fi; \
    else \
      npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest; \
    fi; \
    playwright-cli --help; \
    if [ -n "$PLAYWRIGHT_DOWNLOAD_HOST" ]; then \
      if ! PLAYWRIGHT_DOWNLOAD_HOST="$PLAYWRIGHT_DOWNLOAD_HOST" playwright install --with-deps chromium; then \
        playwright install --with-deps chromium; \
      fi; \
    else \
      playwright install --with-deps chromium; \
    fi; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# doctor / 运行时按可执行文件目录下的 packaging/tools-manifest.json 做工具自检。
COPY packaging/tools-manifest.json /app/packaging/tools-manifest.json
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
