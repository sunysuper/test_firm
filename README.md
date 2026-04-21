# FirmSieve

**两阶段 IoT 固件漏洞分析系统**：用静态污点分析发现漏洞候选，用 LLM Agent 驱动 IDA Pro 验证可控性。

---

## 目录
- [项目简介](#项目简介)
- [工作流程](#工作流程)
- [环境依赖](#环境依赖)
- [Docker 一键启动](#docker-一键启动)
- [安装](#安装)
- [配置](#配置)
- [使用方式](#使用方式)
- [输出结构](#输出结构)
- [故障排查](#故障排查)
- [已知限制](#已知限制)
- [目录结构](#目录结构)
- [引用与致谢](#引用与致谢)

---

## 项目简介

主流的静态污点分析能从 sink（如 `system`、`doSystemCmd`）回溯发现潜在漏洞，但其 **ANI（Assumed-Not-Interesting）** 启发式会跳过大量函数，导致漏报；同时生成的候选 trace 数量多、误报率高，人工审核成本大。

FirmSieve 在此基础上做两件事：

- **Stage 1 · LLM 增强的污点分析**：对 ANI 跳过的函数用 LLM 生成"副作用摘要"，按启发式规则（内存拷贝 API、非栈帧 store、全局段写入）门控 LLM 调用；两级预算控制 + 二级缓存防止成本失控。
- **Stage 2 · LLM Agent 可控性验证**：对 Stage 1 输出的 rank ≥ 7.0 的 closure，用 LLM Agent 通过 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 与 IDA Pro 交互，完成 trace 修正、sink 参数可控性判定、输入通道识别；输出结构化 `VulnSpec` JSON。

**目标架构**：MIPS / ARM 小端（主要是路由器、摄像头等嵌入式设备固件）。
**漏洞类型**：命令注入（`cmdi`）、缓冲区溢出（`overflow`）。

---

## 工作流程

```
┌─────────────────┐      ┌────────────────────────┐      ┌─────────────────────┐
│ 固件二进制       │────▶│         Stage 1        │────▶│ closure (rank≥7.0)  │
│ (MIPS/ARM ELF)  │      │ 静态污点分析 + LLM ANI  │      │ 污点路径候选         │
└─────────────────┘      └────────────────────────┘      └──────────┬──────────┘
                                                               │
                                                               ▼
                        ┌──────────────────────────────────────────────┐
                        │                 Stage 2                      │
                        │  - trace_analyze (LLM + IDA decompile)       │
                        │  - vulnerability_analyze (可控性判定)         │
                        │  - 跨二进制字符串搜索（NVRAM 键、HTTP 参数）    │
                        └───────────────────┬──────────────────────────┘
                                            │
                                            ▼
                        ┌──────────────────────────────────────────────┐
                        │ VulnSpec JSON                                │
                        │  decision = KEEP | DISCARD | DEFER           │
                        │  sink / input_channel / call_chain / 证据     │
                        └──────────────────────────────────────────────┘
```

---

## 环境依赖

### 硬性依赖
| 组件 | 版本 | 说明 |
|---|---|---|
| Python | 3.10+ (Stage1) / 3.11 (Stage2) | Stage2 必须 3.11 以匹配 IDA 9.0 SP1 的 IDAPython |
| angr | 9.2.94 | Stage1 锁定版本 |
| IDA Pro | 9.0 SP1+ 推荐 | 必须 GUI 版 `ida`（非 `idat`）|
| ida-pro-mcp | 1.4.0 | 装在 **user site-packages**（`~/.local/...`）|
| xvfb | 任意 | Linux 下跑无头 IDA 的关键 |

> Linux 下 `idat`（文本模式）在 subprocess 中会触发 `TVision TTY-read failed` 崩溃，**必须**使用 GUI `ida` + `xvfb-run`。

### 可选依赖
- Docker / Kubernetes（Stage1 大规模批处理）
- Ghidra（`GHIDRA_HOME`，某些辅助分析流程）

---

## Docker 一键启动

本仓库提供 Stage 1 + Stage 2 的 `docker-compose` 编排，[`docker/`](docker/) 目录下：

```
docker/
├── stage2/
│   ├── Dockerfile        # Stage 2 运行时镜像（python:3.11-slim + xvfb + ida-pro-mcp）
│   └── entrypoint.sh
├── docker-compose.yml    # 编排 stage1 + stage2
└── .env.example          # 环境变量模板
```


### 1. 前置准备
- 宿主机已安装 IDA Pro 9.0+（目录内含有效 `idapro.hexlic`）
- 已安装 `docker` 和 `docker compose`
- 已有 Stage 1 分析结果（Stage 2 依赖其输出）

### 2. 配置
```bash
cd docker
cp .env.example .env
# 编辑 .env：
#   - 填入 CLAUDE_*_API_KEY 和 LLM_API_KEY
#   - IDA_HOST_PATH 指向宿主机 IDA 安装目录（如 /home/you/IDApro/idapro-9.0）
#   - FIRMSIEVE_FIRMWARE_ROOT 指向具体固件的 squashfs-root（容器内路径，基于 /data/firm/...）
#   - UID/GID 设为 `id -u` / `id -g` 的值
```

### 3. 构建
```bash
docker compose build
```

> 首次构建需要几分钟（apt 装 xvfb 和 Qt 运行时 + pip 装 ida-pro-mcp）。

### 4. 运行

**Stage 1：污点分析**
```bash
docker compose run --rm stage1 sieve /data/firm/<path-to-binary> --results /data/output --concise
```

**Stage 2：LLM Agent 可控性分析**
```bash
# 列出所有待分析任务
docker compose run --rm stage2 --dry-run

# 分析单个任务
docker compose run --rm stage2 --task Tenda_US_AC15V1.0BR_V15.03.05.18_multi_TD01_httpd_cmdi_0xad398

# 批量（2 workers 并行）
docker compose run --rm stage2 --workers 2

# 只看报告
docker compose run --rm stage2 --report
```

### 5. Volume 说明

| 宿主机路径 / 卷 | 容器内路径 | 权限 | 作用 |
|---|---|---|---|
| `${IDA_HOST_PATH}` | `/opt/idapro` | ro | IDA Pro 安装目录（含 license）|
| `stage1/firm/` | `/data/firm` | ro | 固件解包目录 |
| `stage1/output/` | `/data/stage1-output` | ro | Stage 1 结果（Stage 2 读取）|
| `stage2/output/` | `/data/stage2-output` | rw | VulnSpec / 分析日志 |
| `ida_userdata` (named volume) | `/root/.idapro` | rw | IDA 配置持久化（ida.reg、plugin symlink）|

### 6. 常见问题

**Q: license 在容器内失效**
A: IDA node-locked license 可能绑定 hostname。若 license 验证失败，给 `docker compose` 加 `--hostname <your-host>` 或 compose 服务下加 `network_mode: host`。

**Q: 容器写出的 idb 文件在宿主机是 root 所有**
A: 在 `.env` 设置正确的 `UID` / `GID`，并在 `docker-compose.yml` 里取消 `user:` 行的注释。

**Q: Stage 2 报 "端口 13337 持续被占用"**
A: 在容器内端口隔离，该问题通常不会出现。若出现：`docker compose down && docker compose up`。

---

## 安装

> 如果用 Docker，跳到 [Docker 一键启动](#docker-一键启动) 章节。本节是**本地（非容器）**安装方式。

### 系统级
```bash
sudo apt install xvfb
```

### Stage 1
```bash
cd stage1/src/operation-sieve-public-master
python3.10 -m venv venv
source venv/bin/activate
pip install .
```

### Stage 2
```bash
cd stage2
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # 若未提供，参照 stage2/src 导入的包手动装
pip install --user ida-pro-mcp==1.4.0
python3.11 -m ida_pro_mcp --install-plugin      # 创建 ~/.idapro/plugins/mcp-plugin.py symlink
```

> **重要**：`ida-pro-mcp` 必须装到 **user site-packages**（`pip install --user`），否则激活了 Stage2 的 venv 后 IDAPython 找不到模块。

---

## 配置

### Stage 1
```bash
cp stage1/src/operation-sieve-public-master/.env.example \
   stage1/src/operation-sieve-public-master/.env
# 编辑 .env，填入 LLM_API_KEY / LLM_API_BASE / LLM_MODEL
```

### Stage 2
```bash
cp stage2/src/config.example.py stage2/src/config.py
# 编辑 config.py，或通过环境变量注入（推荐）：
export CLAUDE_ANALYSIS_API_KEY=sk-xxx
export CLAUDE_TOOL_API_KEY=sk-xxx
export CLAUDE_BASE_URL=https://your-proxy.example.com/v1
export FIRMSIEVE_FIRMWARE_ROOT=/path/to/your/firmware/squashfs-root
```

两个 Agent 可用同一 key，也可拆开（分析 Agent 用强模型，工具 Agent 用经济模型）。

---

## 使用方式

### Stage 1：污点分析

```bash
cd stage1/src/operation-sieve-public-master
source venv/bin/activate

# 单二进制
sieve /path/to/binary --results output_dir --concise
sieve /path/to/binary --results output_dir --categories cmdi  # 仅命令注入

# 跨二进制环境变量解析
env_resolve /path/to/binary --results output_dir
```

Stage 1 输出目录结构：
```
output/{vendor}/{firmware}/{binary_sha256}/
  ├── cmdi_results.json        # 命令注入 closure 汇总
  ├── overflow_results.json    # 溢出 closure 汇总
  ├── env.json
  └── cmdi_closures/
      └── 70.70_main_0x9f04_system_0xa7c0   # rank_caller_sink 命名
```

### Stage 2：LLM Agent 可控性分析

**前置**：Stage 1 已产出结果，`config.py` 里 `SIEVE_RESULTS_ROOT` / `FIRMWARE_ROOT` 正确。

```bash
cd stage2/src
source ../venv/bin/activate
```

**列出待分析任务**：
```bash
python batch_runner.py --dry-run
```

**分析单个任务**：
```bash
python batch_runner.py --task <TASK_ID>
# 示例：
python batch_runner.py --task Tenda_US_AC15V1.0BR_V15.03.05.18_multi_TD01_httpd_cmdi_0xad398
```

`TASK_ID` 格式：`{vendor}_{firmware}_{binary_name}_{vuln_type}_{sink_addr}`
- `vuln_type` ∈ {`cmdi`, `overflow`}
- `sink_addr` 形如 `0xad398`

**批量分析**：
```bash
python batch_runner.py                    # 单 worker
python batch_runner.py --workers 2        # 2 个 IDA 并行（自动分配端口 13338, 13339, ...）
python batch_runner.py --vendor Tenda --firmware AC15  # 过滤
python batch_runner.py --retry-failed     # 只重跑失败任务
python batch_runner.py --report           # 只输出统计报告
```

**交互式分析**（单二进制调试用）：
```bash
python interaction.py
```

---

## 输出结构

每个 task 完成后在 `stage2/output/log/results/vuln_specs/` 下产生一个 JSON，命名前缀即决策：
- `KEEP_...json`：可控（可被攻击者触发）
- `DISCARD_...json`：不可控（sink 参数为常量 / 受严格校验）
- `DEFER_...json`：Agent 无法判定，需人工复核

### VulnSpec 核心字段
```json
{
  "alert_id": "ALERT-Vendor-binary-sinkaddr",
  "decision": "KEEP",
  "vuln_type": "cmd_injection",
  "target": { "binary": "...", "sink_function": "system", "sink_addr": "0xa7c0" },
  "input_channel": {
    "source_type": "HTTP",
    "protocol": "HTTP", "method": "POST",
    "endpoint": "usbeject",
    "param_key": "dev_name"
  },
  "sink_context": { "code_snippet": "...", "dangerous_chars": [";","|","`","$()"] },
  "dataflow_summary": { "call_chain": ["main","sub_9de8","sub_a6e8"], "taint_propagation": "..." },
  "verification": {
    "reachability":    { "status": "PASS", "evidence": "..." },
    "controllability": { "status": "PASS", "evidence": "..." },
    "attribution":     { "status": "PASS", "evidence": "..." }
  },
  "evidence_digest": "...",
  "metadata": { "confidence": 0.9, "analysis_model": "gpt-5.4" }
}
```

此 JSON 是 Stage 2 与 Stage 3（PoC 生成）之间的**正式接口契约**，定义见 [`stage2/src/vuln_spec.py`](stage2/src/vuln_spec.py)。

同时在 `stage2/output/log/{vendor}/{firmware}/` 下保留每次分析的完整对话日志（`.txt` 人类可读 + `.jsonl` 机器可读），便于审计 Agent 的推理过程。

---

## 故障排查

| 症状 | 原因 | 解决 |
|---|---|---|
| `TVision error: TTY-read failed` | 在 subprocess 里跑 `idat`（文本模式）| 改用 GUI `ida` + `xvfb-run -a` |
| IDA 启动后 75s 不生成 idb，`xwininfo` 显示 Warning 弹窗 | `/tmp/ida/` 有崩溃 minidump，IDA 每次启动都弹提示 | `rm -rf /tmp/ida`（batch_runner 已内置清理）|
| MCP 端口开了但 `get_metadata` hang | `auto_start_mcp.py` 在主线程阻塞，`@idaread` 的 `execute_sync` 被卡 | 确保 `auto_start_mcp.py` 里 **没有** `threading.Event().wait()` |
| `ModuleNotFoundError: No module named 'ida_pro_mcp'` | 激活 Stage2 venv 后 IDAPython 忽略 user site-packages | `auto_start_mcp.py` 会自动把 `~/.local/.../site-packages` 加入 `sys.path`；也可 `pip install ida-pro-mcp==1.4.0` 到 venv 内 |
| 重跑 batch_runner 报"端口 13337 持续被占用" | 上次运行的 IDA 变孤儿进程 | 已用 `start_new_session=True` + `killpg` 修复；若仍发生：`pkill -9 -f /IDApro/` |
| `RuntimeError: IDA Pro 9.0 is missing required Python API methods` | `ida-pro-mcp 2.0.x` 要求 IDA 9.0 SP1+ | 降到 `1.4.0`：`pip install ida-pro-mcp==1.4.0` |
| subprocess 的 stdout PIPE 满导致 IDA 卡住 | batch_runner 用 PIPE 不主动 drain | 已改为重定向到 `/tmp/ida_mcp_{port}.log` |

### 诊断日志
- `/tmp/ida_mcp_{port}.log` — IDA 自身输出（多为空，GUI 模式 print 走 Output Window）
- `/tmp/auto_start_mcp_{port}.log` — `auto_start_mcp.py` 的详细诊断（sys.path、模块加载、异常等）

---

## 已知限制

- 仅支持 **OpenAI 兼容** 的 API（含 Anthropic 中转、DeepSeek 等）；不直接使用 Anthropic 原生 SDK
- IDA 9.0 GUI 模式下单二进制分析需 1–10 分钟（httpd 级别约 600s 上限）
- `ida-pro-mcp 1.4.0` 插件端口 `Server.PORT` 是类属性，多 worker 并行通过环境变量 `IDA_MCP_PORT` + `auto_start_mcp.py` 重写类属性实现
- Stage 2 的 "可控性" 判定依赖 LLM 的 IR 理解能力，对 heavy-obfuscated / 大函数容易 `DEFER`
- 固件文件系统（squashfs-root）需预先解包（binwalk、unsquashfs），本项目不处理解包步骤

---

## 目录结构

```
FirmSieve/
├── README.md                      本文件
├── .gitignore                     排除 venv / firm / output / 敏感配置
│
├── docker/
│   ├── stage2/
│   │   ├── Dockerfile             Stage 2 镜像（python:3.11-slim + xvfb + ida-pro-mcp）
│   │   └── entrypoint.sh
│   ├── docker-compose.yml         编排 stage1 + stage2
│   └── .env.example               Docker 环境变量模板
│
├── stage1/
│   ├── src/operation-sieve-public-master/    静态污点分析 + LLM 增强
│   │   ├── package/argument_resolver/
│   │   │   ├── analysis/sieve.py             核心污点分析引擎
│   │   │   ├── handlers/local_handler.py     LLM 辅助 ANI（两层策略）
│   │   │   └── utils/{llm_client,heuristic_rules}.py
│   │   ├── pipeline/sieve_pipeline/          大规模批处理（Docker/K8s）
│   │   └── .env.example                      LLM key 模板
│   ├── firm/       # (gitignored) 固件解包目录
│   └── output/     # (gitignored) Stage1 分析结果
│
├── stage2/
│   ├── src/
│   │   ├── batch_runner.py                   批量自动化
│   │   ├── interaction.py                    交互式单二进制分析
│   │   ├── auto_start_mcp.py                 IDA 启动时拉起 MCP 的 IDAPython 脚本
│   │   ├── config.example.py                 配置模板
│   │   ├── vuln_spec.py                      VulnSpec 数据类
│   │   ├── analysis_mode/                    Trace 修正 + 可控性分析 Agent
│   │   ├── innovation_tool_mode/             工具执行层（LLM ↔ IDA MCP）
│   │   └── string_database/                  跨二进制字符串搜索
│   └── output/     # (gitignored) 日志 / VulnSpec / 字符串搜索缓存
│
└── 
```

---