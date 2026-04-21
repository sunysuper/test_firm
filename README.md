# FirmSieve

**Two-stage IoT firmware vulnerability analysis system**: discover vulnerability candidates via static taint analysis, then validate controllability using an LLM agent driving IDA Pro.

---

## Table of Contents
- [Overview](#overview)
- [Workflow](#workflow)
- [Requirements](#requirements)
- [Docker Quick Start](#docker-quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Directory Structure](#directory-structure)
- [Citation & Acknowledgements](#citation--acknowledgements)

---

## Overview

Mainstream static taint analysis can backtrack from sinks (such as `system`, `doSystemCmd`) to discover potential vulnerabilities, but its **ANI (Assumed-Not-Interesting)** heuristics skip a large number of functions, causing false negatives; meanwhile, the generated candidate traces are numerous with high false-positive rates, making manual review expensive.

FirmSieve builds on this foundation with two contributions:

- **Stage 1 · LLM-enhanced taint analysis**: Use an LLM to generate "side-effect summaries" for functions skipped by ANI, gated by heuristic rules (memory-copy APIs, non-stack-frame stores, global-segment writes); two-level budget control + two-level caching prevents cost runaway.
- **Stage 2 · LLM Agent controllability verification**: For closures with rank ≥ 7.0 from Stage 1, an LLM agent interacts with IDA Pro through [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) to perform trace correction, sink-argument controllability determination, and input-channel identification; produces a structured `VulnSpec` JSON.

**Target architectures**: MIPS / ARM little-endian (primarily embedded firmware such as routers and cameras).
**Vulnerability types**: command injection (`cmdi`), buffer overflow (`overflow`).

---

## Workflow

```
┌─────────────────┐      ┌────────────────────────┐      ┌─────────────────────┐
│ Firmware binary │────▶│         Stage 1        │────▶│ closure (rank≥7.0)  │
│ (MIPS/ARM ELF)  │      │ Static taint + LLM ANI │      │ Taint path candidate│
└─────────────────┘      └────────────────────────┘      └──────────┬──────────┘
                                                               │
                                                               ▼
                        ┌──────────────────────────────────────────────┐
                        │                 Stage 2                      │
                        │  - trace_analyze (LLM + IDA decompile)       │
                        │  - vulnerability_analyze (controllability)   │
                        │  - Cross-binary string search (NVRAM / HTTP) │
                        └───────────────────┬──────────────────────────┘
                                            │
                                            ▼
                        ┌──────────────────────────────────────────────┐
                        │ VulnSpec JSON                                │
                        │  decision = KEEP | DISCARD | DEFER           │
                        │  sink / input_channel / call_chain / evidence│
                        └──────────────────────────────────────────────┘
```

---

## Requirements

### Hard requirements
| Component | Version | Notes |
|---|---|---|
| Python | 3.10+ (Stage1) / 3.11 (Stage2) | Stage 2 must use 3.11 to match IDAPython in IDA 9.0 SP1 |
| angr | 9.2.94 | Pinned version for Stage 1 |
| IDA Pro | 9.0 SP1+ recommended | GUI `ida` required (not `idat`) |
| ida-pro-mcp | 1.4.0 | Installed in **user site-packages** (`~/.local/...`) |
| xvfb | any | Required for running headless IDA on Linux |

> On Linux, `idat` (text mode) crashes with `TVision TTY-read failed` when invoked from a subprocess. You **must** use GUI `ida` + `xvfb-run`.

### Optional dependencies
- Docker / Kubernetes (for large-scale Stage 1 batch analysis)
- Ghidra (`GHIDRA_HOME`, used by some auxiliary analysis flows)

---

## Docker Quick Start

This repository provides `docker-compose` orchestration for Stage 1 + Stage 2 under the [`docker/`](docker/) directory:

```
docker/
├── stage2/
│   ├── Dockerfile        # Stage 2 runtime image (python:3.11-slim + xvfb + ida-pro-mcp)
│   └── entrypoint.sh
├── docker-compose.yml    # Orchestrates stage1 + stage2
└── .env.example          # Environment variable template
```


### 1. Prerequisites
- IDA Pro 9.0+ installed on the host (with a valid `idapro.hexlic` in the install directory)
- `docker` and `docker compose` installed
- Stage 1 analysis results available (Stage 2 depends on them)

### 2. Configuration
```bash
cd docker
cp .env.example .env
# Edit .env:
#   - Fill in CLAUDE_*_API_KEY and LLM_API_KEY
#   - IDA_HOST_PATH points to the host IDA install directory (e.g. /home/you/IDApro/idapro-9.0)
#   - FIRMSIEVE_FIRMWARE_ROOT points to the squashfs-root of a specific firmware (container path, under /data/firm/...)
#   - UID/GID set to `id -u` / `id -g`
```

### 3. Build
```bash
docker compose build
```

> First build takes several minutes (apt installs xvfb and Qt runtime + pip installs ida-pro-mcp).

### 4. Run

**Stage 1: taint analysis**
```bash
docker compose run --rm stage1 sieve /data/firm/<path-to-binary> --results /data/output --concise
```

**Stage 2: LLM-agent controllability analysis**
```bash
# List all tasks to analyze
docker compose run --rm stage2 --dry-run

# Analyze a single task
docker compose run --rm stage2 --task Tenda_US_AC15V1.0BR_V15.03.05.18_multi_TD01_httpd_cmdi_0xad398

# Batch (2 parallel workers)
docker compose run --rm stage2 --workers 2

# Report only
docker compose run --rm stage2 --report
```

### 5. Volumes

| Host path / volume | Container path | Permission | Purpose |
|---|---|---|---|
| `${IDA_HOST_PATH}` | `/opt/idapro` | ro | IDA Pro install directory (includes license) |
| `stage1/firm/` | `/data/firm` | ro | Firmware unpack directory |
| `stage1/output/` | `/data/stage1-output` | ro | Stage 1 results (read by Stage 2) |
| `stage2/output/` | `/data/stage2-output` | rw | VulnSpec / analysis logs |
| `ida_userdata` (named volume) | `/root/.idapro` | rw | IDA config persistence (ida.reg, plugin symlink) |

### 6. FAQ

**Q: License is invalid inside the container**
A: An IDA node-locked license may be bound to the hostname. If license validation fails, pass `--hostname <your-host>` to `docker compose`, or add `network_mode: host` to the compose service.

**Q: idb files written from the container are owned by root on the host**
A: Set the correct `UID` / `GID` in `.env` and uncomment the `user:` line in `docker-compose.yml`.

**Q: Stage 2 reports "port 13337 is persistently occupied"**
A: Ports are isolated inside containers, so this is usually not an issue. If it happens: `docker compose down && docker compose up`.

---

## Installation

> If you use Docker, skip to the [Docker Quick Start](#docker-quick-start) section. This section describes **local (non-containerized)** installation.

### System level
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
pip install -r requirements.txt   # If not provided, install packages manually by checking imports under stage2/src
pip install --user ida-pro-mcp==1.4.0
python3.11 -m ida_pro_mcp --install-plugin      # Creates ~/.idapro/plugins/mcp-plugin.py symlink
```

> **Important**: `ida-pro-mcp` must be installed into **user site-packages** (`pip install --user`), otherwise IDAPython cannot find the module once Stage 2's venv is activated.

---

## Configuration

### Stage 1
```bash
cp stage1/src/operation-sieve-public-master/.env.example \
   stage1/src/operation-sieve-public-master/.env
# Edit .env, fill in LLM_API_KEY / LLM_API_BASE / LLM_MODEL
```

### Stage 2
```bash
cp stage2/src/config.example.py stage2/src/config.py
# Edit config.py, or inject via environment variables (recommended):
export CLAUDE_ANALYSIS_API_KEY=sk-xxx
export CLAUDE_TOOL_API_KEY=sk-xxx
export CLAUDE_BASE_URL=https://your-proxy.example.com/v1
export FIRMSIEVE_FIRMWARE_ROOT=/path/to/your/firmware/squashfs-root
```

The two agents can share a single key or use separate ones (stronger model for the analysis agent, cheaper model for the tool agent).

---

## Usage

### Stage 1: taint analysis

```bash
cd stage1/src/operation-sieve-public-master
source venv/bin/activate

# Single binary
sieve /path/to/binary --results output_dir --concise
sieve /path/to/binary --results output_dir --categories cmdi  # Command injection only

# Cross-binary environment variable resolution
env_resolve /path/to/binary --results output_dir
```

Stage 1 output directory layout:
```
output/{vendor}/{firmware}/{binary_sha256}/
  ├── cmdi_results.json        # Command-injection closure summary
  ├── overflow_results.json    # Overflow closure summary
  ├── env.json
  └── cmdi_closures/
      └── 70.70_main_0x9f04_system_0xa7c0   # Naming: rank_caller_sink
```

### Stage 2: LLM-agent controllability analysis

**Prerequisites**: Stage 1 results are available, and `SIEVE_RESULTS_ROOT` / `FIRMWARE_ROOT` in `config.py` are correct.

```bash
cd stage2/src
source ../venv/bin/activate
```

**List pending tasks**:
```bash
python batch_runner.py --dry-run
```

**Analyze a single task**:
```bash
python batch_runner.py --task <TASK_ID>
# Example:
python batch_runner.py --task Tenda_US_AC15V1.0BR_V15.03.05.18_multi_TD01_httpd_cmdi_0xad398
```

`TASK_ID` format: `{vendor}_{firmware}_{binary_name}_{vuln_type}_{sink_addr}`
- `vuln_type` ∈ {`cmdi`, `overflow`}
- `sink_addr` looks like `0xad398`

**Batch analysis**:
```bash
python batch_runner.py                    # Single worker
python batch_runner.py --workers 2        # 2 IDA instances in parallel (ports 13338, 13339, ... assigned automatically)
python batch_runner.py --vendor Tenda --firmware AC15  # Filtering
python batch_runner.py --retry-failed     # Re-run failed tasks only
python batch_runner.py --report           # Output statistics only
```

**Interactive analysis** (single-binary debugging):
```bash
python interaction.py
```

---

## Output Structure

After each task completes, a JSON is produced under `stage2/output/log/results/vuln_specs/`, with the filename prefix indicating the decision:
- `KEEP_...json`: controllable (attacker-triggerable)
- `DISCARD_...json`: not controllable (sink argument is constant or strictly validated)
- `DEFER_...json`: the agent cannot decide; requires manual review

### Core VulnSpec fields
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

This JSON is the **formal interface contract** between Stage 2 and Stage 3 (PoC generation); see [`stage2/src/vuln_spec.py`](stage2/src/vuln_spec.py).

Full conversation logs for every analysis are also preserved under `stage2/output/log/{vendor}/{firmware}/` (`.txt` human-readable + `.jsonl` machine-readable), to allow auditing the agent's reasoning process.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `TVision error: TTY-read failed` | Running `idat` (text mode) in a subprocess | Use GUI `ida` + `xvfb-run -a` instead |
| IDA fails to generate an idb within 75s; `xwininfo` shows a Warning dialog | A crash minidump in `/tmp/ida/` triggers a pop-up on every IDA start | `rm -rf /tmp/ida` (batch_runner already performs this cleanup) |
| MCP port opens but `get_metadata` hangs | `auto_start_mcp.py` blocks the main thread, and `execute_sync` of `@idaread` gets stuck | Make sure `auto_start_mcp.py` does **not** call `threading.Event().wait()` |
| `ModuleNotFoundError: No module named 'ida_pro_mcp'` | IDAPython ignores user site-packages after activating Stage 2's venv | `auto_start_mcp.py` automatically prepends `~/.local/.../site-packages` to `sys.path`; alternatively install `ida-pro-mcp==1.4.0` into the venv |
| Re-running batch_runner reports "port 13337 persistently occupied" | The previous IDA became an orphan process | Fixed via `start_new_session=True` + `killpg`; if it still happens: `pkill -9 -f /IDApro/` |
| `RuntimeError: IDA Pro 9.0 is missing required Python API methods` | `ida-pro-mcp 2.0.x` requires IDA 9.0 SP1+ | Downgrade to `1.4.0`: `pip install ida-pro-mcp==1.4.0` |
| IDA hangs because the subprocess stdout PIPE fills up | batch_runner used PIPE without draining | Now redirected to `/tmp/ida_mcp_{port}.log` |

### Diagnostic logs
- `/tmp/ida_mcp_{port}.log` — IDA's own output (mostly empty; in GUI mode `print` goes to the Output Window)
- `/tmp/auto_start_mcp_{port}.log` — detailed diagnostics from `auto_start_mcp.py` (sys.path, module loading, exceptions, etc.)

---

## Known Limitations

- Only **OpenAI-compatible** APIs are supported (Anthropic proxies, DeepSeek, etc.); the native Anthropic SDK is not used directly
- Under IDA 9.0 GUI mode, single-binary analysis takes 1–10 minutes (httpd-class binaries up to ~600s)
- In `ida-pro-mcp 1.4.0`, `Server.PORT` is a class attribute; multi-worker parallelism rewrites this class attribute via the `IDA_MCP_PORT` environment variable combined with `auto_start_mcp.py`
- Stage 2's "controllability" determination relies on the LLM's IR-understanding ability and tends to `DEFER` on heavily obfuscated / very large functions
- Firmware filesystems (squashfs-root) must be unpacked in advance (binwalk, unsquashfs); this project does not handle the unpack step

---

## Directory Structure

```
FirmSieve/
├── README.md                      This file
├── .gitignore                     Excludes venv / firm / output / sensitive config
│
├── docker/
│   ├── stage2/
│   │   ├── Dockerfile             Stage 2 image (python:3.11-slim + xvfb + ida-pro-mcp)
│   │   └── entrypoint.sh
│   ├── docker-compose.yml         Orchestrates stage1 + stage2
│   └── .env.example               Docker environment variable template
│
├── stage1/
│   ├── src/operation-sieve-public-master/    Static taint analysis + LLM enhancement
│   │   ├── package/argument_resolver/
│   │   │   ├── analysis/sieve.py             Core taint analysis engine
│   │   │   ├── handlers/local_handler.py     LLM-assisted ANI (two-layer strategy)
│   │   │   └── utils/{llm_client,heuristic_rules}.py
│   │   ├── pipeline/sieve_pipeline/          Large-scale batch processing (Docker/K8s)
│   │   └── .env.example                      LLM key template
│   ├── firm/       # (gitignored) firmware unpack directory
│   └── output/     # (gitignored) Stage 1 analysis results
│
├── stage2/
│   ├── src/
│   │   ├── batch_runner.py                   Batch automation
│   │   ├── interaction.py                    Interactive single-binary analysis
│   │   ├── auto_start_mcp.py                 IDAPython script that launches MCP at IDA startup
│   │   ├── config.example.py                 Configuration template
│   │   ├── vuln_spec.py                      VulnSpec dataclass
│   │   ├── analysis_mode/                    Trace correction + controllability analysis agents
│   │   ├── innovation_tool_mode/             Tool execution layer (LLM ↔ IDA MCP)
│   │   └── string_database/                  Cross-binary string search
│   └── output/     # (gitignored) logs / VulnSpec / string-search cache
│
└── 
```

---
