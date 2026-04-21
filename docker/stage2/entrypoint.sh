#!/bin/bash
# Stage 2 容器入口：保证 ~/.idapro 的 plugin symlink 存在，然后启动 batch_runner。
set -e

# 若 ~/.idapro 是 volume 挂载点，镜像构建时的 plugin symlink 可能被覆盖。
# 重新执行一次 install-plugin（幂等）。
mkdir -p "$HOME/.idapro/plugins"
python3.11 -m ida_pro_mcp --install-plugin 2>/dev/null || true

# IDA 首次启动会写 ~/.idapro/ida.reg，需要可写目录
if [ ! -w "$HOME/.idapro" ]; then
    echo "[entrypoint] ERROR: $HOME/.idapro 不可写，请确认 volume 权限或 --user UID 正确" >&2
    exit 1
fi

# 所有参数透传给 batch_runner.py
exec python3.11 batch_runner.py "$@"
