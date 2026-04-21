# FirmSieve Stage 2 运行时镜像
#
# IDA Pro 9.0+ 不打包到镜像中（商业软件），由用户以 bind mount 方式提供：
#   docker run -v /host/IDApro/idapro-9.0:/opt/idapro:ro firmsieve/stage2
#
# IDA Pro 9.0 内置 libpython3.11.so，因此镜像必须使用 Python 3.11。

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# -- 系统依赖 --
# xvfb:            无头 X server（GUI ida 必需）
# libmagic1:       python-magic 的运行时依赖
# libglib2.0-0 / libgl1 / libfontconfig1 / libxkbcommon0 / libdbus-1-3 / libx*:
#                  IDA GUI 的 Qt 运行时依赖
# procps:          batch_runner 里用 ps/pgrep 诊断
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb \
        libmagic1 \
        libglib2.0-0 libgl1 libfontconfig1 libxkbcommon0 libdbus-1-3 \
        libxrender1 libxi6 libxtst6 libsm6 libice6 libxrandr2 libxcursor1 libxinerama1 \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -- Python 依赖 --
# ida-pro-mcp 必须是 1.4.0（2.0.x 要求 IDA 9.0 SP1+ 的 API）
RUN pip install --no-cache-dir \
        "ida-pro-mcp==1.4.0" \
        openai \
        pydantic \
        python-magic

# -- 项目代码 --
WORKDIR /app
COPY stage2/src /app/stage2/src

# -- IDA 插件 symlink --
# 镜像层里先创建一次（若运行时 ~/.idapro 被 volume 覆盖，entrypoint 会再执行一次）
RUN python3.11 -m ida_pro_mcp --install-plugin

# -- 默认环境变量 --
# IDA 可执行文件（以 bind mount 方式挂入 /opt/idapro）
ENV IDA_EXECUTABLE_PATH=/opt/idapro/ida \
    MCP_HOST=127.0.0.1 \
    MCP_PORT=13337

COPY docker/stage2/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app/stage2/src
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
