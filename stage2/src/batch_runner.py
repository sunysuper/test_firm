#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDACMP 批量自动化漏洞分析脚本
遍历 Operation Sieve 结果，按二进制文件分组，自动加载 IDA Pro 并执行分析。
每个漏洞生成独立日志文件，支持断点续传。
"""

import os
import sys
import json
import time
import queue
import datetime
import traceback
import subprocess
import argparse
import multiprocessing
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import config as _config
IDA_EXECUTABLE_PATH = _config.IDA_EXECUTABLE_PATH
MCP_HOST = _config.MCP_HOST
BASE_MCP_PORT = _config.MCP_PORT  # 基础端口，并行时按 +i 分配

# ===== 常量配置（从 config.py 读取，不再硬编码） =====
RESULTS_ROOT = _config.SIEVE_RESULTS_ROOT
FIRMWARE_ROOT = _config.FIRMWARE_ROOT
LOG_ROOT = os.path.dirname(_config.LOG_FILE_PATH)
STRING_SEARCH_DIR = _config.STRING_SEARCH_RESULTS_DIR
PROGRESS_FILE = os.path.join(LOG_ROOT, "batch_progress.json")

LINUX_PATH_PREFIX = getattr(_config, "LINUX_PATH_PREFIX", "")
MIN_RANK = 7.0
VULN_TYPES = [
    ("cmdi_results.json", "cmdi"),
    ("overflow_results.json", "overflow"),
]

IDA_STARTUP_WAIT = 60       # IDA初始等待秒数
IDA_MCP_CHECK_RETRIES = 20  # MCP连接重试次数（大文件需要更多重试）
IDA_MCP_CHECK_INTERVAL = 15 # 每次重试间隔秒数
AUTO_MCP_SCRIPT = os.path.join(PROJECT_ROOT, "auto_start_mcp.py")
API_COOLDOWN = 10           # 每个漏洞分析完成后冷却秒数（防止API限流）


# ===== 数据结构 =====

@dataclass
class VulnerabilityTask:
    """单个漏洞分析任务"""
    vendor: str
    firmware: str
    sha256: str
    binary_name: str
    binary_linux_path: str
    vuln_type: str          # "cmdi" 或 "overflow"
    sink_addr: str          # 如 "0xae38"
    sink_function: str      # 如 "system"
    rank: float
    trace: list
    sink: dict
    closure_index: int
    reachable_from_main: bool = False
    sanitized: bool = False

    @property
    def binary_key(self) -> str:
        """二进制文件唯一标识（基于路径）"""
        return self.binary_linux_path

    @property
    def task_id(self) -> str:
        """漏洞任务唯一ID"""
        return f"{self.vendor}_{self.firmware}_{self.binary_name}_{self.vuln_type}_{self.sink_addr}"

    @property
    def binary_dir(self) -> str:
        """提取二进制文件在固件中的目录路径（squashfs-root之后，文件名之前）"""
        parts = self.binary_linux_path.split('/')
        sqidx = -1
        for i, p in enumerate(parts):
            if p == 'squashfs-root':
                sqidx = i
                break
        if sqidx >= 0 and sqidx + 2 < len(parts):
            # squashfs-root 之后到文件名之前的路径，用短横线连接
            dir_parts = parts[sqidx + 1:-1]
            return '-'.join(dir_parts)
        return 'unknown'

    @property
    def log_filename(self) -> str:
        """生成日志文件名"""
        return f"{self.vendor}_{self.firmware}_{self.binary_dir}_{self.binary_name}_{self.vuln_type}_{self.sink_addr}.txt"


@dataclass
class BinaryGroup:
    """按二进制文件分组的漏洞任务集合"""
    binary_linux_path: str
    binary_name: str
    vendor: str
    firmware: str
    tasks: list = field(default_factory=list)
    local_path: Optional[str] = None


# ===== 任务扫描 =====

def scan_all_tasks(vendor_filter=None, firmware_filter=None) -> list:
    """扫描结果目录，构建按二进制文件分组的任务列表"""
    binary_groups = {}

    for vendor in os.listdir(RESULTS_ROOT):
        vendor_path = os.path.join(RESULTS_ROOT, vendor)
        if not os.path.isdir(vendor_path):
            continue
        # 跳过非目录项（如 results.csv, symbols.json, vendors.json）
        if vendor in ("results.csv", "symbols.json", "vendors.json"):
            continue
        if vendor_filter and vendor != vendor_filter:
            continue

        for firmware in os.listdir(vendor_path):
            fw_path = os.path.join(vendor_path, firmware)
            if not os.path.isdir(fw_path):
                continue
            if firmware_filter and firmware != firmware_filter:
                continue

            for sha_dir in os.listdir(fw_path):
                sha_path = os.path.join(fw_path, sha_dir)
                if not os.path.isdir(sha_path):
                    continue

                for result_file, vuln_type in VULN_TYPES:
                    fpath = os.path.join(sha_path, result_file)
                    if not os.path.exists(fpath):
                        continue

                    try:
                        with open(fpath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        print(f"  [WARN] JSON解析失败: {fpath}: {e}")
                        continue

                    closures = data.get("closures", [])
                    binary_name = data.get("name", "unknown")
                    binary_path = data.get("path", "")

                    # 如果结果文件中没有 name/path，尝试从 env.json 获取
                    if binary_name == "unknown" or not binary_path:
                        env_path = os.path.join(sha_path, "env.json")
                        if os.path.exists(env_path):
                            try:
                                with open(env_path, 'r', encoding='utf-8') as ef:
                                    env_data = json.load(ef)
                                if binary_name == "unknown":
                                    binary_name = env_data.get("name", "unknown")
                                if not binary_path:
                                    binary_path = env_data.get("path", "")
                            except:
                                pass

                    if not binary_path:
                        continue

                    for idx, closure in enumerate(closures):
                        rank = closure.get("rank", 0)
                        if rank < MIN_RANK:
                            continue

                        sink = closure.get("sink", {})
                        task = VulnerabilityTask(
                            vendor=vendor,
                            firmware=firmware,
                            sha256=sha_dir,
                            binary_name=binary_name,
                            binary_linux_path=binary_path,
                            vuln_type=vuln_type,
                            sink_addr=sink.get("ins_addr", "unknown"),
                            sink_function=sink.get("function", "unknown"),
                            rank=rank,
                            trace=closure.get("trace", []),
                            sink=sink,
                            closure_index=idx,
                            reachable_from_main=closure.get("reachable_from_main", False),
                            sanitized=closure.get("sanitized", False),
                        )

                        key = task.binary_key
                        if key not in binary_groups:
                            binary_groups[key] = BinaryGroup(
                                binary_linux_path=binary_path,
                                binary_name=binary_name,
                                vendor=vendor,
                                firmware=firmware,
                            )
                        binary_groups[key].tasks.append(task)

    # 去重：同一 sink 地址可能由不同 trace 到达，只保留 rank 最高的
    for group in binary_groups.values():
        seen = {}
        for task in group.tasks:
            tid = task.task_id
            if tid not in seen or task.rank > seen[tid].rank:
                seen[tid] = task
        group.tasks = list(seen.values())

    # 按总 rank 降序排列，优先处理高危二进制
    groups = list(binary_groups.values())
    groups.sort(key=lambda g: sum(t.rank for t in g.tasks), reverse=True)
    return groups


# ===== 路径映射 =====

def resolve_local_path(linux_path: str) -> Optional[str]:
    """将 Sieve 结果中的路径转换为本地路径"""
    if linux_path.startswith(LINUX_PATH_PREFIX):
        relative = linux_path[len(LINUX_PATH_PREFIX):]
        local = os.path.join(FIRMWARE_ROOT, relative)
        if os.path.exists(local):
            return local

    # 回退：按文件名搜索
    binary_name = os.path.basename(linux_path)
    for root, dirs, files in os.walk(FIRMWARE_ROOT):
        if binary_name in files:
            found = os.path.join(root, binary_name)
            return found

    return None


def get_squashfs_root(linux_path: str) -> Optional[str]:
    """从 Linux 路径提取 squashfs-root 的本地路径，用于更新 FIRMWARE_ROOT"""
    if not linux_path.startswith(LINUX_PATH_PREFIX):
        return None

    relative = linux_path[len(LINUX_PATH_PREFIX):]
    parts = relative.split('/')

    # 找到 squashfs-root 的位置
    for i, p in enumerate(parts):
        if p == 'squashfs-root':
            sqroot_relative = '/'.join(parts[:i + 1])
            local = os.path.join(FIRMWARE_ROOT, sqroot_relative)
            if os.path.isdir(local):
                return local
            break

    return None


# ===== IDA Pro 管理 =====

class IDAManager:
    """管理 IDA Pro 进程生命周期"""

    def __init__(self, port=None):
        self.ida_path = IDA_EXECUTABLE_PATH
        self.port = port or BASE_MCP_PORT
        self.current_process = None
        self.current_binary = None

    def start_ida(self, binary_path: str) -> bool:
        """启动新的 IDA Pro 实例"""
        self.stop_ida()

        if not os.path.exists(binary_path):
            print(f"  [ERROR] 二进制文件不存在: {binary_path}")
            return False

        # 清理残留的 IDA 数据库碎片（上次崩溃留下的）
        self._cleanup_stale_idb(binary_path)

        # 清理 IDA 崩溃 minidump（否则 GUI 启动会弹出 "previously IDA crashed" 警告阻塞）
        minidump_dir = "/tmp/ida"
        if os.path.isdir(minidump_dir):
            try:
                removed = 0
                for name in os.listdir(minidump_dir):
                    if name.endswith(".dmp"):
                        os.remove(os.path.join(minidump_dir, name))
                        removed += 1
                if removed:
                    print(f"  [IDA] 清理 {removed} 个 minidump 文件")
            except Exception as e:
                print(f"  [WARN] 清理 minidump 失败: {e}")

        # 确保端口可用
        if self._is_port_in_use():
            print(f"  [IDA] 端口 {self.port} 被占用，等待释放...")
            for _ in range(6):
                time.sleep(5)
                if not self._is_port_in_use():
                    break
            else:
                print(f"  [ERROR] 端口 {self.port} 持续被占用")
                return False

        # 根据文件大小估算等待时间：每100KB约10秒，最少60秒，最多600秒
        file_size_kb = os.path.getsize(binary_path) / 1024
        wait_time = max(IDA_STARTUP_WAIT, int(file_size_kb / 100 * 10))
        wait_time = min(wait_time, 600)  # 上限10分钟（大文件如httpd ~1MB）

        print(f"  [IDA] 启动 IDA Pro: {os.path.basename(binary_path)} ({file_size_kb:.0f}KB) port={self.port}")
        try:
            # -A: 自动分析  -S: 分析完成后自动启动 MCP 服务器
            cmd = ["xvfb-run", "-a", self.ida_path, "-A", f"-S{AUTO_MCP_SCRIPT}", binary_path]
            env = os.environ.copy()
            env["IDA_MCP_PORT"] = str(self.port)
            env["IDA_MCP_HOST"] = MCP_HOST
            # 用文件而非 PIPE 捕获 IDA 输出 —— PIPE 缓冲满会导致 IDA write 阻塞，
            # 永远走不到 MCP 启动。文件方式可以边写边增长不阻塞。
            self._log_path = f"/tmp/ida_mcp_{self.port}.log"
            self._log_fh = open(self._log_path, "w")
            self.current_process = subprocess.Popen(
                cmd,
                stdout=self._log_fh,
                stderr=subprocess.STDOUT,
                env=env,
                # 建新 process group，stop 时可 killpg 整组（xvfb-run + Xvfb + ida）
                # 否则 terminate 只杀 xvfb-run 外壳，ida 孙子进程变孤儿继续占端口
                start_new_session=True,
                **({"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {})
            )
        except Exception as e:
            print(f"  [ERROR] IDA启动失败: {e}")
            return False

        print(f"  [IDA] 等待IDA分析完成 ({wait_time}s)...")
        # 分段等待，定期检查进程是否还活着
        elapsed = 0
        ida_exited_early = False
        while elapsed < wait_time:
            chunk = min(15, wait_time - elapsed)
            time.sleep(chunk)
            elapsed += chunk
            if self.current_process and self.current_process.poll() is not None:
                rc = self.current_process.returncode
                ida_exited_early = True
                print(f"  [WARN] IDA 进程提前退出 (returncode={rc})，继续检查MCP...")
                break

        # 检查 MCP 连接
        for attempt in range(IDA_MCP_CHECK_RETRIES):
            if self._check_mcp():
                self.current_binary = binary_path
                print(f"  [IDA] MCP连接成功 (第{attempt + 1}次尝试)")
                return True
            # 如果IDA已退出且不是第一次重试，减少等待
            if ida_exited_early and attempt >= 3:
                print(f"  [IDA] IDA已退出且MCP无响应，停止重试")
                break
            print(f"  [IDA] MCP未就绪, 重试 {attempt + 1}/{IDA_MCP_CHECK_RETRIES}...")
            time.sleep(IDA_MCP_CHECK_INTERVAL)

        # 失败时输出诊断信息
        self._dump_ida_output()
        print("  [ERROR] MCP连接失败，已达最大重试次数")
        self.stop_ida()
        return False

    @staticmethod
    def _cleanup_stale_idb(binary_path: str):
        """清理上次 IDA 崩溃留下的数据库碎片文件（.id0/.id1/.id2/.nam/.til）"""
        stale_exts = [".id0", ".id1", ".id2", ".nam", ".til"]
        cleaned = []
        for ext in stale_exts:
            f = binary_path + ext
            if os.path.exists(f):
                try:
                    os.remove(f)
                    cleaned.append(ext)
                except Exception:
                    pass
        if cleaned:
            print(f"  [IDA] 清理残留数据库碎片: {', '.join(cleaned)}")

    def _dump_ida_output(self):
        """打印 IDA 日志文件尾部用于诊断"""
        log_path = getattr(self, "_log_path", None)
        if not log_path or not os.path.exists(log_path):
            return
        try:
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 2000))
                tail = f.read().decode("utf-8", errors="replace")
            if tail:
                print(f"  [IDA-DIAG] log tail ({log_path}):\n{tail}")
        except Exception:
            pass

    def _check_mcp(self) -> bool:
        """检查 IDA MCP JSON-RPC 服务器是否响应"""
        try:
            import http.client
            conn = http.client.HTTPConnection(MCP_HOST, self.port, timeout=10)
            request = json.dumps({
                "jsonrpc": "2.0",
                "method": "get_metadata",
                "params": [],
                "id": 1
            })
            conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            conn.close()
            return "result" in data
        except Exception:
            return False

    def _is_port_in_use(self) -> bool:
        """检查 MCP 端口是否被占用"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((MCP_HOST, self.port)) == 0

    def stop_ida(self):
        """终止当前 IDA Pro 实例（以及 xvfb-run 下的所有子进程）"""
        if self.current_process:
            pid = self.current_process.pid
            try:
                # killpg 整个 process group，以防 xvfb-run 的孙子（真正的 ida）变孤儿
                import signal
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    self.current_process.terminate()
                self.current_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except Exception:
                    self.current_process.kill()
            except Exception:
                pass
            self.current_process = None
            self.current_binary = None
            time.sleep(3)
        fh = getattr(self, "_log_fh", None)
        if fh:
            try:
                fh.close()
            except Exception:
                pass
            self._log_fh = None


# ===== 进度跟踪（断点续传） =====

class ProgressTracker:
    """跟踪已完成的任务，支持断点续传"""

    def __init__(self, progress_file: str):
        self.progress_file = progress_file
        self.completed = {}
        self.failed = {}
        self.load()

    def load(self):
        """从磁盘加载进度"""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.completed = data.get("completed", {})
                self.failed = data.get("failed", {})
                print(f"  [RESUME] 已加载进度: {len(self.completed)} 已完成, {len(self.failed)} 失败")
            except Exception as e:
                print(f"  [WARN] 加载进度文件失败: {e}")

    def save(self):
        """持久化进度到磁盘"""
        os.makedirs(os.path.dirname(self.progress_file), exist_ok=True)
        data = {
            "completed": self.completed,
            "failed": self.failed,
            "last_updated": datetime.datetime.now().isoformat()
        }
        with open(self.progress_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def is_completed(self, task_id: str) -> bool:
        return task_id in self.completed

    def mark_completed(self, task_id: str, result: str):
        self.completed[task_id] = {
            "result": result,
            "timestamp": datetime.datetime.now().isoformat()
        }
        # 清除旧的失败记录
        self.failed.pop(task_id, None)
        self.save()

    def mark_failed(self, task_id: str, error: str):
        self.failed[task_id] = {
            "error": error,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.save()

    def clear_all_failed(self):
        """清除所有失败记录，使这些任务在下次运行时被重新分析"""
        count = len(self.failed)
        self.failed.clear()
        self.save()
        return count

    def get_failed_task_ids(self) -> set:
        """返回所有失败任务的 task_id 集合"""
        return set(self.failed.keys())

    def clear_by_result(self, result_value: str) -> int:
        """清除所有匹配指定结果的已完成记录，使其变为待处理。返回清除数量。"""
        to_remove = [tid for tid, info in self.completed.items()
                     if info.get("result") == result_value]
        for tid in to_remove:
            del self.completed[tid]
        if to_remove:
            self.save()
        return len(to_remove)


# ===== 日志管理 =====

def get_log_path(task: VulnerabilityTask) -> str:
    """构建漏洞日志文件的完整路径"""
    log_dir = os.path.join(LOG_ROOT, task.vendor, task.firmware)
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, task.log_filename)


# ===== 动态配置更新 =====

def update_config_for_binary(group: BinaryGroup):
    """为当前二进制文件更新配置（FIRMWARE_ROOT 指向对应的 squashfs-root）"""
    import config

    sqroot = get_squashfs_root(group.binary_linux_path)
    if sqroot:
        config.update_firmware_root(sqroot)
        print(f"  [CONFIG] FIRMWARE_ROOT -> {sqroot}")
    else:
        print(f"  [WARN] 未找到 squashfs-root, 保持默认 FIRMWARE_ROOT")

    # 设置字符串搜索结果目录（按厂商/固件分隔）
    string_dir = os.path.join(STRING_SEARCH_DIR, group.vendor, group.firmware)
    os.makedirs(string_dir, exist_ok=True)
    config.update_string_search_dir(string_dir)


# ===== 单个漏洞分析 =====

def _format_trace_for_log(trace: list, sink: dict) -> str:
    """将 trace 和 sink 格式化为可读的多行文本"""
    lines = []
    lines.append("Trace Path:")
    for i, entry in enumerate(trace):
        func = entry.get("function", "?")
        addr = entry.get("ins_addr", "?")
        call_str = entry.get("string", "")
        # 截断过长的 BV/MultiValues 表达式
        if len(call_str) > 120:
            call_str = call_str[:120] + "..."
        lines.append(f"  [{i}] {func} @ {addr}")
        if call_str:
            lines.append(f"      {call_str}")
    lines.append(f"\nSink:")
    lines.append(f"  Function: {sink.get('function', '?')}")
    lines.append(f"  Address:  {sink.get('ins_addr', '?')}")
    sink_str = sink.get("string", "")
    if sink_str:
        if len(sink_str) > 200:
            sink_str = sink_str[:200] + "..."
        lines.append(f"  Call:     {sink_str}")
    return "\n".join(lines)


def analyze_single_vulnerability(task: VulnerabilityTask, log_file: str) -> str:
    """
    执行单个漏洞的完整分析流程。
    返回: "controllable", "uncontrollable", 或 "unknown"
    同时生成 VulnSpec JSON 文件。
    """
    from analysis_mode.trace_analyze import analyze_trace
    from analysis_mode.vulnerability_analyze import analyze_vulnerability
    from innovation_tool_mode.execute_tools import tools_call
    from interaction import TraceAnalysisAgent, AnalysisAgent, extract_source
    from stage2_output import Stage2OutputManager
    import config as _cfg

    analysis_start = time.time()

    # 写入日志头部
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("IDACMP Vulnerability Analysis Log\n")
        f.write("=" * 60 + "\n")
        f.write(f"Timestamp:    {datetime.datetime.now().isoformat()}\n")
        f.write(f"Binary:       {task.binary_name}\n")
        f.write(f"Vendor:       {task.vendor}\n")
        f.write(f"Firmware:     {task.firmware}\n")
        f.write(f"Vuln Type:    {task.vuln_type}\n")
        f.write(f"Sink:         {task.sink_function} @ {task.sink_addr}\n")
        f.write(f"Rank:         {task.rank}\n")
        f.write(f"Reachable:    {task.reachable_from_main}\n")
        f.write(f"Sanitized:    {task.sanitized}\n")
        f.write(f"Analysis Model: {getattr(_cfg, 'CLAUDE_ANALYSIS_MODEL', 'N/A')}\n")
        f.write(f"Tool Model:     {getattr(_cfg, 'CLAUDE_TOOL_MODEL', 'N/A')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(_format_trace_for_log(task.trace, task.sink))
        f.write("\n\n")

    # ===== PHASE 1: Trace 分析 =====
    phase1_start = time.time()
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("[PHASE 1] Trace Analysis\n")
        f.write("=" * 60 + "\n")

    print(f"    [TRACE] 分析 {task.sink_function} @ {task.sink_addr}")
    trace_agent = TraceAnalysisAgent(
        analysis_model=analyze_trace,
        tool_model=tools_call,
        res_file=log_file
    )
    trace_result = trace_agent.process(task.trace, task.sink)
    source = extract_source(trace_result)
    phase1_time = time.time() - phase1_start

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"[PHASE 1 RESULT] Extracted Source (耗时 {phase1_time:.1f}s)\n")
        f.write(f"{source}\n")
        f.write(f"{'=' * 60}\n\n")

    # ===== PHASE 2: 可控性分析 =====
    phase2_start = time.time()
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("[PHASE 2] Vulnerability Controllability Analysis\n")
        f.write("=" * 60 + "\n")

    print(f"    [VULN] 可控性分析...")
    vuln_agent = AnalysisAgent(
        analysis_model=analyze_vulnerability,
        tool_model=tools_call,
        res_file=log_file
    )
    # process() 现在返回 (conclusion, last_llm_response) 元组
    result, last_llm_response = vuln_agent.process(task.trace, source)
    phase2_time = time.time() - phase2_start
    total_time = time.time() - analysis_start

    # ===== 推断 DEFER 原因码 (文档4.2.5.2) =====
    defer_reason = "INSUFFICIENT_EVIDENCE"
    if result == "unknown":
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                log_text = f.read()
            log_lower = log_text.lower()
            if "熔断退出" in log_text or "mcp 持续断开" in log_text or "connection error" in log_lower:
                defer_reason = "TOOL_FAILURE"
            elif "达到最大迭代次数" in log_text or "达到最大轮次" in log_text or "budget" in log_lower:
                defer_reason = "BUDGET_EXCEEDED"
            elif "反编译失败" in log_text or "decompile" in log_lower and "fail" in log_lower:
                defer_reason = "DECOMPILE_FAILED"
        except Exception:
            pass

    # ===== 生成 VulnSpec JSON =====
    try:
        output_mgr = Stage2OutputManager(LOG_ROOT)
        spec = output_mgr.build_vuln_spec(
            vendor=task.vendor,
            firmware=task.firmware,
            binary_name=task.binary_name,
            binary_path=task.binary_linux_path,
            vuln_type=task.vuln_type,
            sink_function=task.sink_function,
            sink_addr=task.sink_addr,
            rank=task.rank,
            trace=task.trace,
            sink=task.sink,
            analysis_result=result,
            llm_response=last_llm_response,
            analysis_model=getattr(_cfg, 'CLAUDE_ANALYSIS_MODEL', ''),
            tool_model=getattr(_cfg, 'CLAUDE_TOOL_MODEL', ''),
            interaction_log_path=os.path.relpath(log_file, LOG_ROOT).replace("\\", "/"),
            defer_reason=defer_reason,
        )
        spec_path = output_mgr.save_spec(spec)
        print(f"    [SPEC] {spec.decision.value} -> {os.path.basename(spec_path)}")
    except Exception as e:
        print(f"    [WARN] VulnSpec生成失败: {e}")
        spec_path = None

    # ===== 日志尾部 =====
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"[FINAL RESULT] {result}\n")
        f.write(f"Phase 1 (Trace):         {phase1_time:.1f}s\n")
        f.write(f"Phase 2 (Controllability): {phase2_time:.1f}s\n")
        f.write(f"Total:                   {total_time:.1f}s\n")
        if spec_path:
            f.write(f"VulnSpec:                {os.path.basename(spec_path)}\n")
        f.write(f"Completed: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n")

    return result


# ===== Dry-run 报告 =====

def print_dry_run_report(groups: list, tracker: ProgressTracker):
    """只扫描显示任务列表，不执行分析"""
    total_tasks = sum(len(g.tasks) for g in groups)
    pending = sum(1 for g in groups for t in g.tasks if not tracker.is_completed(t.task_id))

    print(f"\n{'=' * 70}")
    print(f"IDACMP 批量分析 - Dry Run 报告")
    print(f"{'=' * 70}")
    print(f"二进制文件数: {len(groups)}")
    print(f"漏洞总数:     {total_tasks}")
    print(f"待处理:       {pending}")
    print(f"已完成:       {len(tracker.completed)}")
    print(f"已失败:       {len(tracker.failed)}")

    # 按厂商统计
    vendor_stats = {}
    for g in groups:
        v = g.vendor
        if v not in vendor_stats:
            vendor_stats[v] = {"binaries": 0, "tasks": 0, "pending": 0}
        vendor_stats[v]["binaries"] += 1
        vendor_stats[v]["tasks"] += len(g.tasks)
        vendor_stats[v]["pending"] += sum(1 for t in g.tasks if not tracker.is_completed(t.task_id))

    print(f"\n{'厂商':<15} {'二进制':>8} {'漏洞':>8} {'待处理':>8}")
    print("-" * 45)
    for v, s in sorted(vendor_stats.items()):
        print(f"{v:<15} {s['binaries']:>8} {s['tasks']:>8} {s['pending']:>8}")

    # 显示每个二进制的详情
    print(f"\n{'=' * 70}")
    print("二进制文件详情:")
    print(f"{'=' * 70}")
    for g in groups:
        resolved = resolve_local_path(g.binary_linux_path)
        status = "OK" if resolved else "NOT FOUND"
        pending_count = sum(1 for t in g.tasks if not tracker.is_completed(t.task_id))
        print(f"\n[{g.vendor}/{g.firmware}] {g.binary_name} ({len(g.tasks)}个漏洞, {pending_count}待处理) [{status}]")
        if resolved:
            print(f"  Local: {resolved}")
        else:
            print(f"  Linux: {g.binary_linux_path}")
        for t in g.tasks:
            done = "DONE" if tracker.is_completed(t.task_id) else "PEND"
            print(f"  [{done}] {t.vuln_type} | {t.sink_function} @ {t.sink_addr} | rank={t.rank}")
            print(f"         Log: {t.log_filename}")


def print_results_report(vendor_filter=None, firmware_filter=None):
    """生成分析结果统计报告，输出到终端和文件"""
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    tracker = ProgressTracker(PROGRESS_FILE)

    if not tracker.completed and not tracker.failed:
        print("[REPORT] 暂无分析结果")
        return

    # 建立 task_id → task 元信息映射
    task_map = {}
    for g in groups:
        for t in g.tasks:
            task_map[t.task_id] = t

    # 分类统计
    controllable = []   # (task_id, task_or_None, timestamp)
    uncontrollable = []
    unknown = []
    failed = []

    for task_id, info in tracker.completed.items():
        result = info.get("result", "unknown")
        task = task_map.get(task_id)
        entry = (task_id, task, info.get("timestamp", ""))
        if result == "controllable":
            controllable.append(entry)
        elif result == "uncontrollable":
            uncontrollable.append(entry)
        else:
            unknown.append(entry)

    for task_id, info in tracker.failed.items():
        task = task_map.get(task_id)
        failed.append((task_id, task, info.get("error", ""), info.get("timestamp", "")))

    total_completed = len(controllable) + len(uncontrollable) + len(unknown)
    total_all = total_completed + len(failed)

    # ===== 生成报告文本 =====
    lines = []
    def w(s=""):
        lines.append(s)

    w("=" * 70)
    w("IDACMP 漏洞分析结果统计报告")
    w(f"生成时间: {datetime.datetime.now().isoformat()}")
    w("=" * 70)

    w(f"\n一、全局概览")
    w("-" * 40)
    w(f"  分析总数:       {total_all}")
    w(f"  已完成:         {total_completed}")
    w(f"    可控 (controllable):       {len(controllable)}")
    w(f"    不可控 (uncontrollable):   {len(uncontrollable)}")
    w(f"    未知 (unknown):            {len(unknown)}")
    w(f"  失败:           {len(failed)}")
    if total_completed > 0:
        ctrl_rate = len(controllable) / total_completed * 100
        w(f"  可控率:         {ctrl_rate:.1f}%")

    # ===== 按厂商统计 =====
    w(f"\n二、按厂商统计")
    w("-" * 40)
    vendor_stats = {}
    for task_id, task, _ in controllable + uncontrollable + unknown:
        v = task.vendor if task else task_id.split("_")[0]
        if v not in vendor_stats:
            vendor_stats[v] = {"controllable": 0, "uncontrollable": 0, "unknown": 0}
        result = "controllable" if (task_id, task, _) in controllable else ("uncontrollable" if (task_id, task, _) in uncontrollable else "unknown")

    # 重新统计（上面的 in 判断在 tuple 里不可靠）
    vendor_stats = {}
    for task_id, task, ts in controllable:
        v = task.vendor if task else task_id.split("_")[0]
        vendor_stats.setdefault(v, {"controllable": 0, "uncontrollable": 0, "unknown": 0, "failed": 0})
        vendor_stats[v]["controllable"] += 1
    for task_id, task, ts in uncontrollable:
        v = task.vendor if task else task_id.split("_")[0]
        vendor_stats.setdefault(v, {"controllable": 0, "uncontrollable": 0, "unknown": 0, "failed": 0})
        vendor_stats[v]["uncontrollable"] += 1
    for task_id, task, ts in unknown:
        v = task.vendor if task else task_id.split("_")[0]
        vendor_stats.setdefault(v, {"controllable": 0, "uncontrollable": 0, "unknown": 0, "failed": 0})
        vendor_stats[v]["unknown"] += 1
    for task_id, task, err, ts in failed:
        v = task.vendor if task else task_id.split("_")[0]
        vendor_stats.setdefault(v, {"controllable": 0, "uncontrollable": 0, "unknown": 0, "failed": 0})
        vendor_stats[v]["failed"] += 1

    w(f"  {'厂商':<12} {'可控':>6} {'不可控':>6} {'未知':>6} {'失败':>6} {'合计':>6} {'可控率':>8}")
    w(f"  {'-'*58}")
    for v in sorted(vendor_stats.keys()):
        s = vendor_stats[v]
        total_v = s["controllable"] + s["uncontrollable"] + s["unknown"]
        all_v = total_v + s["failed"]
        rate = f"{s['controllable']/total_v*100:.1f}%" if total_v > 0 else "N/A"
        w(f"  {v:<12} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {s['failed']:>6} {all_v:>6} {rate:>8}")

    # ===== 按漏洞类型统计 =====
    w(f"\n三、按漏洞类型统计")
    w("-" * 40)
    type_stats = {}
    for task_id, task, ts in controllable:
        vt = task.vuln_type if task else ("cmdi" if "_cmdi_" in task_id else "overflow")
        type_stats.setdefault(vt, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        type_stats[vt]["controllable"] += 1
    for task_id, task, ts in uncontrollable:
        vt = task.vuln_type if task else ("cmdi" if "_cmdi_" in task_id else "overflow")
        type_stats.setdefault(vt, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        type_stats[vt]["uncontrollable"] += 1
    for task_id, task, ts in unknown:
        vt = task.vuln_type if task else ("cmdi" if "_cmdi_" in task_id else "overflow")
        type_stats.setdefault(vt, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        type_stats[vt]["unknown"] += 1

    w(f"  {'类型':<12} {'可控':>6} {'不可控':>6} {'未知':>6} {'合计':>6} {'可控率':>8}")
    w(f"  {'-'*50}")
    for vt in sorted(type_stats.keys()):
        s = type_stats[vt]
        total_vt = s["controllable"] + s["uncontrollable"] + s["unknown"]
        rate = f"{s['controllable']/total_vt*100:.1f}%" if total_vt > 0 else "N/A"
        w(f"  {vt:<12} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {total_vt:>6} {rate:>8}")

    # ===== 按 sink 函数统计 =====
    w(f"\n四、按 Sink 函数统计")
    w("-" * 40)
    sink_stats = {}
    for task_id, task, ts in controllable:
        sf = task.sink_function if task else "?"
        sink_stats.setdefault(sf, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        sink_stats[sf]["controllable"] += 1
    for task_id, task, ts in uncontrollable:
        sf = task.sink_function if task else "?"
        sink_stats.setdefault(sf, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        sink_stats[sf]["uncontrollable"] += 1
    for task_id, task, ts in unknown:
        sf = task.sink_function if task else "?"
        sink_stats.setdefault(sf, {"controllable": 0, "uncontrollable": 0, "unknown": 0})
        sink_stats[sf]["unknown"] += 1

    w(f"  {'Sink函数':<20} {'可控':>6} {'不可控':>6} {'未知':>6} {'合计':>6} {'可控率':>8}")
    w(f"  {'-'*58}")
    for sf in sorted(sink_stats.keys(), key=lambda x: -(sink_stats[x]["controllable"] + sink_stats[x]["uncontrollable"] + sink_stats[x]["unknown"])):
        s = sink_stats[sf]
        total_sf = s["controllable"] + s["uncontrollable"] + s["unknown"]
        rate = f"{s['controllable']/total_sf*100:.1f}%" if total_sf > 0 else "N/A"
        w(f"  {sf:<20} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {total_sf:>6} {rate:>8}")

    # ===== 可控漏洞清单（重点审查） =====
    w(f"\n五、可控漏洞清单 (共{len(controllable)}个，需人工审查是否误报)")
    w("=" * 70)
    # 按厂商+固件分组显示
    ctrl_by_vendor = {}
    for task_id, task, ts in controllable:
        v = task.vendor if task else "?"
        fw = task.firmware if task else "?"
        ctrl_by_vendor.setdefault(v, {}).setdefault(fw, []).append((task_id, task, ts))

    for v in sorted(ctrl_by_vendor.keys()):
        for fw in sorted(ctrl_by_vendor[v].keys()):
            w(f"\n  [{v}/{fw}]")
            for task_id, task, ts in ctrl_by_vendor[v][fw]:
                if task:
                    w(f"    {task.vuln_type:<10} {task.sink_function}@{task.sink_addr}  rank={task.rank}  binary={task.binary_name}")
                    w(f"    {'':10} 路径: {task.binary_dir}/{task.binary_name}")
                    w(f"    {'':10} 日志: {task.log_filename}")
                else:
                    w(f"    {task_id}")

    # ===== 未知结果清单 =====
    if unknown:
        w(f"\n六、未知结果清单 (共{len(unknown)}个，需人工审查)")
        w("=" * 70)
        for task_id, task, ts in unknown:
            if task:
                w(f"  {task.vendor}/{task.firmware}: {task.vuln_type} {task.sink_function}@{task.sink_addr} binary={task.binary_name}")
                w(f"    日志: {task.log_filename}")
            else:
                w(f"  {task_id}")

    # ===== 失败清单 =====
    if failed:
        section = "七" if unknown else "六"
        w(f"\n{section}、失败任务清单 (共{len(failed)}个)")
        w("=" * 70)
        # 按错误类型分组
        error_groups = {}
        for task_id, task, err, ts in failed:
            short_err = err[:60] if len(err) > 60 else err
            error_groups.setdefault(short_err, []).append((task_id, task))

        for err, tasks in sorted(error_groups.items(), key=lambda x: -len(x[1])):
            w(f"\n  错误: {err} ({len(tasks)}个)")
            for task_id, task in tasks:
                name = f"{task.binary_name} ({task.vuln_type} {task.sink_function}@{task.sink_addr})" if task else task_id
                w(f"    - {name}")

    w(f"\n{'=' * 70}")

    # 输出到终端
    report_text = "\n".join(lines)
    print(report_text)

    # 保存到文件
    report_file = os.path.join(LOG_ROOT, "analysis_results_report.txt")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\n报告已保存: {report_file}")


# ===== 主执行循环 =====

def run_batch(vendor_filter=None, firmware_filter=None):
    """主批量执行入口"""
    print("=" * 70)
    print("IDACMP 批量自动化漏洞分析")
    print(f"启动时间: {datetime.datetime.now().isoformat()}")
    if vendor_filter:
        print(f"厂商过滤: {vendor_filter}")
    if firmware_filter:
        print(f"固件过滤: {firmware_filter}")
    print("=" * 70)

    # 步骤1: 扫描任务
    print("\n[SCAN] 扫描结果目录...")
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    total_tasks = sum(len(g.tasks) for g in groups)
    print(f"[SCAN] 发现 {len(groups)} 个二进制文件, {total_tasks} 个高危漏洞")

    if not groups:
        print("[DONE] 未发现需要分析的漏洞")
        return

    # 步骤2: 解析本地路径
    print("\n[PATH] 解析本地二进制文件路径...")
    valid_groups = []
    skipped_binaries = 0
    for group in groups:
        local = resolve_local_path(group.binary_linux_path)
        if local:
            group.local_path = local
            valid_groups.append(group)
        else:
            skipped_binaries += 1
            print(f"  [SKIP] 文件未找到: {group.binary_name} ({group.vendor}/{group.firmware})")

    valid_tasks = sum(len(g.tasks) for g in valid_groups)
    print(f"[PATH] {len(valid_groups)} 个二进制可用 ({valid_tasks} 个漏洞), "
          f"{skipped_binaries} 个跳过")

    # 步骤3: 加载进度
    tracker = ProgressTracker(PROGRESS_FILE)
    remaining = sum(1 for g in valid_groups for t in g.tasks if not tracker.is_completed(t.task_id))
    print(f"\n[RESUME] 剩余 {remaining} 个任务 (共 {valid_tasks} 个)")

    if remaining == 0:
        print("[DONE] 所有任务已完成!")
        return

    # 步骤4: 执行分析
    ida = IDAManager(port=BASE_MCP_PORT)
    stats = {
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "controllable": 0,
        "uncontrollable": 0,
        "unknown": 0,
    }
    start_time = time.time()

    try:
        for g_idx, group in enumerate(valid_groups):
            pending_tasks = [t for t in group.tasks if not tracker.is_completed(t.task_id)]
            if not pending_tasks:
                stats["skipped"] += len(group.tasks)
                continue

            print(f"\n{'=' * 60}")
            print(f"[BINARY {g_idx + 1}/{len(valid_groups)}] {group.binary_name}")
            print(f"  厂商: {group.vendor} | 固件: {group.firmware}")
            print(f"  路径: {group.local_path}")
            print(f"  任务: {len(pending_tasks)} 待处理 / {len(group.tasks)} 总计")
            print(f"{'=' * 60}")

            # 更新配置
            update_config_for_binary(group)

            # 清除 MCP 查询缓存（切换二进制文件）
            try:
                from innovation_tool_mode.tools import clear_cache
                clear_cache()
            except ImportError:
                pass

            # 启动 IDA
            if not ida.start_ida(group.local_path):
                print(f"  [ERROR] IDA启动失败, 跳过 {group.binary_name}")
                for task in pending_tasks:
                    tracker.mark_failed(task.task_id, "IDA startup failed")
                    stats["failed"] += 1
                continue

            # 分析每个漏洞
            for t_idx, task in enumerate(pending_tasks):
                log_file = get_log_path(task)
                print(f"\n  --- 漏洞 {t_idx + 1}/{len(pending_tasks)} ---")
                print(f"  类型: {task.vuln_type} | Sink: {task.sink_function} @ {task.sink_addr} | Rank: {task.rank}")
                print(f"  日志: {task.log_filename}")

                try:
                    result = analyze_single_vulnerability(task, log_file)
                    tracker.mark_completed(task.task_id, result)
                    stats["completed"] += 1
                    if result == "controllable":
                        stats["controllable"] += 1
                    elif result == "uncontrollable":
                        stats["uncontrollable"] += 1
                    else:
                        stats["unknown"] += 1
                    print(f"  [RESULT] {result}")
                    time.sleep(API_COOLDOWN)

                except Exception as e:
                    error_msg = f"{type(e).__name__}: {str(e)}"
                    print(f"  [ERROR] {error_msg}")

                    # 可重试错误：429限流、5xx服务端错误、连接错误
                    is_rate_limit = "429" in str(e) or "rate_limit" in str(e).lower()
                    is_server_error = any(code in str(e) for code in ["500", "502", "503", "504", "Bad gateway", "bad gateway"])
                    is_connection_error = "APIConnectionError" in type(e).__name__ or "Connection error" in str(e) or "ConnectionError" in type(e).__name__

                    if is_rate_limit or is_server_error or is_connection_error:
                        wait_time = 30 if is_rate_limit else 60
                        max_retries = 2
                        reason = "API限流" if is_rate_limit else ("连接错误" if is_connection_error else "服务端错误(502)")

                        for retry in range(max_retries):
                            print(f"  [RETRY] {reason}，等待{wait_time}秒后重试 ({retry+1}/{max_retries})...")
                            time.sleep(wait_time)
                            try:
                                result = analyze_single_vulnerability(task, log_file)
                                tracker.mark_completed(task.task_id, result)
                                stats["completed"] += 1
                                if result == "controllable":
                                    stats["controllable"] += 1
                                elif result == "uncontrollable":
                                    stats["uncontrollable"] += 1
                                else:
                                    stats["unknown"] += 1
                                print(f"  [RESULT] 重试成功: {result}")
                                time.sleep(API_COOLDOWN)
                                break
                            except Exception as e2:
                                error_msg = f"{type(e2).__name__}: {str(e2)}"
                                print(f"  [ERROR] 重试{retry+1}失败: {error_msg}")
                                wait_time = min(wait_time * 2, 120)  # 指数退避，上限2分钟
                        else:
                            # 所有重试均失败
                            tracker.mark_failed(task.task_id, error_msg)
                            stats["failed"] += 1
                            continue

                        continue  # 重试成功，跳过下面的失败处理

                    tracker.mark_failed(task.task_id, error_msg)
                    stats["failed"] += 1

                    # 错误写入日志
                    try:
                        with open(log_file, "a", encoding="utf-8") as f:
                            f.write(f"\n[ERROR] {error_msg}\n")
                            f.write(traceback.format_exc())
                    except:
                        pass

            # 当前二进制分析完毕，关闭 IDA
            ida.stop_ida()
            print(f"\n  [DONE] {group.binary_name} 分析完毕")

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] 用户中断，正在安全关闭...")
        ida.stop_ida()
    finally:
        ida.stop_ida()

    # 步骤5: 汇总报告
    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"批量分析完成")
    print(f"{'=' * 70}")
    print(f"耗时:         {elapsed / 3600:.1f} 小时 ({elapsed:.0f}秒)")
    print(f"已完成:       {stats['completed']}")
    print(f"  可控:       {stats['controllable']}")
    print(f"  不可控:     {stats['uncontrollable']}")
    print(f"  未知:       {stats['unknown']}")
    print(f"失败:         {stats['failed']}")
    print(f"跳过(已完成): {stats['skipped']}")
    print(f"进度文件:     {PROGRESS_FILE}")
    print(f"日志目录:     {LOG_ROOT}")
    print(f"{'=' * 70}")


# ===== 多进程并行分析 =====

def _analyze_with_retry(task, log_file):
    """执行单个漏洞分析，含 429/5xx 重试逻辑。返回 (status, result_or_error)"""
    try:
        result = analyze_single_vulnerability(task, log_file)
        return ("completed", result)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        err_str = str(e)

        is_rate_limit = "429" in err_str or "rate_limit" in err_str.lower()
        is_server_error = any(code in err_str for code in ["500", "502", "503", "504", "Bad gateway", "bad gateway"])
        is_connection_error = "APIConnectionError" in type(e).__name__ or "Connection error" in err_str or "ConnectionError" in type(e).__name__

        if is_rate_limit or is_server_error or is_connection_error:
            wait_time = 30 if is_rate_limit else 60
            max_retries = 2
            reason = "API限流" if is_rate_limit else ("连接错误" if is_connection_error else "服务端错误")

            for retry in range(max_retries):
                print(f"  [RETRY] {reason}，等待{wait_time}秒后重试 ({retry+1}/{max_retries})...")
                time.sleep(wait_time)
                try:
                    result = analyze_single_vulnerability(task, log_file)
                    return ("completed", result)
                except Exception as e2:
                    error_msg = f"{type(e2).__name__}: {str(e2)}"
                    print(f"  [ERROR] 重试{retry+1}失败: {error_msg}")
                    wait_time = min(wait_time * 2, 120)

        # 错误写入日志
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n[ERROR] {error_msg}\n")
                f.write(traceback.format_exc())
        except:
            pass
        return ("failed", error_msg)


def worker_process(worker_id, port, task_queue, result_queue):
    """
    子进程入口：从队列取二进制组，逐个分析漏洞。
    每个 worker 拥有独立的 Python 模块全局变量空间。
    """
    import config
    config.update_mcp_port(port)

    prefix = f"[W{worker_id}]"
    print(f"{prefix} Worker启动, MCP端口={port}")

    ida = IDAManager(port=port)

    while True:
        try:
            item = task_queue.get(timeout=5)
        except:
            # 队列为空且超时，检查是否还有任务
            if task_queue.empty():
                break
            continue

        if item is None:
            # 毒丸信号，退出
            break

        group, pending_task_ids = item
        pending_tasks = [t for t in group.tasks if t.task_id in pending_task_ids]

        print(f"\n{prefix} {'=' * 50}")
        print(f"{prefix} 二进制: {group.binary_name} ({group.vendor}/{group.firmware})")
        print(f"{prefix} 任务数: {len(pending_tasks)}")
        print(f"{prefix} {'=' * 50}")

        # 更新当前进程的配置
        update_config_for_binary(group)

        # 清除 MCP 查询缓存（切换二进制文件）
        try:
            from innovation_tool_mode.tools import clear_cache
            clear_cache()
        except ImportError:
            pass

        # 启动 IDA
        if not ida.start_ida(group.local_path):
            print(f"{prefix} [ERROR] IDA启动失败, 跳过 {group.binary_name}")
            for task in pending_tasks:
                result_queue.put((task.task_id, "failed", "IDA startup failed"))
            continue

        # 分析每个漏洞
        for t_idx, task in enumerate(pending_tasks):
            log_file = get_log_path(task)
            print(f"\n{prefix} --- 漏洞 {t_idx+1}/{len(pending_tasks)} ---")
            print(f"{prefix} {task.vuln_type} | {task.sink_function} @ {task.sink_addr} | rank={task.rank}")

            status, result = _analyze_with_retry(task, log_file)
            result_queue.put((task.task_id, status, result))
            print(f"{prefix} [RESULT] {status}: {result}")

            if status == "completed":
                time.sleep(API_COOLDOWN)

        # 当前二进制分析完毕
        ida.stop_ida()
        print(f"{prefix} [DONE] {group.binary_name} 分析完毕")

    ida.stop_ida()
    print(f"{prefix} Worker退出")


def run_batch_parallel(vendor_filter=None, firmware_filter=None, num_workers=2):
    """多进程并行批量执行入口"""
    print("=" * 70)
    print(f"IDACMP 批量自动化漏洞分析 (并行模式, {num_workers} workers)")
    print(f"启动时间: {datetime.datetime.now().isoformat()}")
    if vendor_filter:
        print(f"厂商过滤: {vendor_filter}")
    if firmware_filter:
        print(f"固件过滤: {firmware_filter}")
    print("=" * 70)

    # 步骤1: 扫描任务
    print("\n[SCAN] 扫描结果目录...")
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    total_tasks = sum(len(g.tasks) for g in groups)
    print(f"[SCAN] 发现 {len(groups)} 个二进制文件, {total_tasks} 个高危漏洞")

    if not groups:
        print("[DONE] 未发现需要分析的漏洞")
        return

    # 步骤2: 解析本地路径
    print("\n[PATH] 解析本地二进制文件路径...")
    valid_groups = []
    for group in groups:
        local = resolve_local_path(group.binary_linux_path)
        if local:
            group.local_path = local
            valid_groups.append(group)
        else:
            print(f"  [SKIP] 文件未找到: {group.binary_name} ({group.vendor}/{group.firmware})")

    valid_tasks = sum(len(g.tasks) for g in valid_groups)
    print(f"[PATH] {len(valid_groups)} 个二进制可用 ({valid_tasks} 个漏洞)")

    # 步骤3: 加载进度，过滤已完成的任务
    tracker = ProgressTracker(PROGRESS_FILE)

    pending_groups = []
    for group in valid_groups:
        pending_ids = set(t.task_id for t in group.tasks if not tracker.is_completed(t.task_id))
        if pending_ids:
            pending_groups.append((group, pending_ids))

    remaining = sum(len(ids) for _, ids in pending_groups)
    print(f"\n[RESUME] 剩余 {remaining} 个任务 (共 {valid_tasks} 个)")

    if remaining == 0:
        print("[DONE] 所有任务已完成!")
        return

    # 步骤4: 创建队列，启动 workers
    task_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()

    for group, pending_ids in pending_groups:
        task_queue.put((group, pending_ids))

    # 放入毒丸信号
    for _ in range(num_workers):
        task_queue.put(None)

    # 启动 worker 进程
    workers = []
    for i in range(num_workers):
        port = BASE_MCP_PORT + i
        p = multiprocessing.Process(
            target=worker_process,
            args=(i, port, task_queue, result_queue),
            name=f"worker-{i}"
        )
        p.start()
        workers.append(p)
        print(f"[MAIN] Worker {i} 已启动 (PID={p.pid}, port={port})")

    # 步骤5: 主进程收集结果
    stats = {
        "completed": 0, "failed": 0,
        "controllable": 0, "uncontrollable": 0, "unknown": 0,
    }
    start_time = time.time()

    try:
        while True:
            # 检查是否所有 worker 都已退出
            alive = [w for w in workers if w.is_alive()]
            try:
                task_id, status, result = result_queue.get(timeout=3)
            except:
                if not alive and result_queue.empty():
                    break
                continue

            if status == "completed":
                tracker.mark_completed(task_id, result)
                stats["completed"] += 1
                if result == "controllable":
                    stats["controllable"] += 1
                elif result == "uncontrollable":
                    stats["uncontrollable"] += 1
                else:
                    stats["unknown"] += 1
            else:
                tracker.mark_failed(task_id, result)
                stats["failed"] += 1

            done = stats["completed"] + stats["failed"]
            print(f"[MAIN] 进度: {done}/{remaining} (成功:{stats['completed']} 失败:{stats['failed']})")

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] 用户中断，正在终止所有worker...")
        for w in workers:
            w.terminate()

    # 等待所有 worker 退出
    for w in workers:
        w.join(timeout=30)
        if w.is_alive():
            w.kill()

    # 步骤6: 汇总报告
    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"批量分析完成 (并行模式, {num_workers} workers)")
    print(f"{'=' * 70}")
    print(f"耗时:         {elapsed / 3600:.1f} 小时 ({elapsed:.0f}秒)")
    print(f"已完成:       {stats['completed']}")
    print(f"  可控:       {stats['controllable']}")
    print(f"  不可控:     {stats['uncontrollable']}")
    print(f"  未知:       {stats['unknown']}")
    print(f"失败:         {stats['failed']}")
    print(f"进度文件:     {PROGRESS_FILE}")
    print(f"日志目录:     {LOG_ROOT}")
    print(f"{'=' * 70}")

def main():
    parser = argparse.ArgumentParser(
        description="IDACMP 批量自动化漏洞分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python batch_runner.py --dry-run              # 只扫描显示任务
  python batch_runner.py --vendor Tenda         # 只处理Tenda厂商 (单进程)
  python batch_runner.py --workers 2            # 2个IDA并行分析
  python batch_runner.py --workers 3 --vendor Tenda  # 3并行+厂商过滤
  python batch_runner.py --reset-progress       # 清除进度重新开始
  python batch_runner.py --retry-failed         # 只重试之前失败的任务
  python batch_runner.py --report               # 生成分析结果统计报告
  python batch_runner.py --recheck controllable # 重新分析所有"可控"结果
  python batch_runner.py --recheck controllable --vendor Tenda  # 只重新分析Tenda的可控结果
  python batch_runner.py --task Tenda_..._httpd_cmdi_0xad398   # 重新分析单条任务
        """
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="只扫描显示任务列表，不执行分析")
    parser.add_argument("--vendor", type=str,
                        help="只处理指定厂商 (如: Tenda, d-link, NETGEAR, TP_Link)")
    parser.add_argument("--firmware", type=str,
                        help="只处理指定固件 (需配合 --vendor 使用)")
    parser.add_argument("--workers", type=int, default=1,
                        help="并行worker数量 (默认1=串行, >=2启用多进程并行)")
    parser.add_argument("--reset-progress", action="store_true",
                        help="清除进度文件，重新开始")
    parser.add_argument("--retry-failed", action="store_true",
                        help="只重试之前失败的任务")
    parser.add_argument("--report", action="store_true",
                        help="生成分析结果统计报告（含可控漏洞清单、误报审查用）")
    parser.add_argument("--recheck", type=str, metavar="RESULT",
                        choices=["controllable", "uncontrollable", "unknown", "all"],
                        help="重新分析指定结果的任务 (controllable/uncontrollable/unknown/all)")
    parser.add_argument("--task", type=str, metavar="TASK_ID",
                        help="重新分析单个任务 (task_id, 如: Tenda_US_AC15..._httpd_cmdi_0xad398)")
    parser.add_argument("--auto-retry", action="store_true",
                        help="第一轮完成后自动重试失败的任务（默认等待120秒后重试）")
    parser.add_argument("--retry-delay", type=int, default=120,
                        help="自动重试前等待秒数 (默认120秒, 配合 --auto-retry)")

    args = parser.parse_args()

    if args.reset_progress and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
        print("[RESET] 进度已清除")

    if args.dry_run:
        groups = scan_all_tasks(args.vendor, args.firmware)
        tracker = ProgressTracker(PROGRESS_FILE)
        print_dry_run_report(groups, tracker)
        return

    if args.report:
        print_results_report(args.vendor, args.firmware)
        return

    # 如果是 --task，只分析这一条任务然后退出
    if args.task:
        tracker = ProgressTracker(PROGRESS_FILE)
        tid = args.task
        # 清除旧记录
        if tid in tracker.completed:
            old = tracker.completed.pop(tid)
            tracker.save()
            print(f"[RECHECK] 已清除任务 '{tid}' (原结果: {old.get('result', '?')})")
        elif tid in tracker.failed:
            tracker.failed.pop(tid)
            tracker.save()
            print(f"[RECHECK] 已清除失败任务 '{tid}'")

        # 扫描找到对应的任务
        groups = scan_all_tasks(args.vendor, args.firmware)
        target_task = None
        target_group = None
        for g in groups:
            for t in g.tasks:
                if t.task_id == tid:
                    target_task = t
                    target_group = g
                    break
            if target_task:
                break

        if not target_task:
            print(f"[ERROR] 未找到任务 '{tid}'")
            print(f"  提示: 使用 --dry-run 查看所有可用的 task_id")
            return

        # 解析本地路径
        local = resolve_local_path(target_group.binary_linux_path)
        if not local:
            print(f"[ERROR] 二进制文件未找到: {target_group.binary_linux_path}")
            return
        target_group.local_path = local

        # 更新配置、启动 IDA、分析、退出
        update_config_for_binary(target_group)

        # 清除 MCP 查询缓存
        try:
            from innovation_tool_mode.tools import clear_cache
            clear_cache()
        except ImportError:
            pass

        ida = IDAManager()
        try:
            if not ida.start_ida(local):
                print(f"[ERROR] IDA启动失败")
                tracker.mark_failed(tid, "IDA startup failed")
                return

            log_file = get_log_path(target_task)
            print(f"\n[TASK] {target_task.vuln_type} | {target_task.sink_function} @ {target_task.sink_addr}")
            print(f"[TASK] 日志: {log_file}")

            result = analyze_single_vulnerability(target_task, log_file)
            tracker.mark_completed(tid, result)
            print(f"\n[RESULT] {result}")
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            print(f"[ERROR] {error_msg}")
            tracker.mark_failed(tid, error_msg)
        finally:
            ida.stop_ida()
        return

    # 如果是 --retry-failed，清除失败记录后正常执行
    if args.retry_failed:
        tracker = ProgressTracker(PROGRESS_FILE)
        failed_ids = tracker.get_failed_task_ids()
        if not failed_ids:
            print("[RETRY] 没有失败的任务需要重试")
            return
        count = tracker.clear_all_failed()
        print(f"[RETRY] 已清除 {count} 条失败记录，开始重试...")

    # 如果是 --recheck，清除指定结果后正常执行
    if args.recheck:
        tracker = ProgressTracker(PROGRESS_FILE)
        # 如果指定了 --vendor/--firmware，只清除匹配的任务
        vendor_prefix = f"{args.vendor}_" if args.vendor else None
        firmware_prefix = f"{args.firmware}_" if args.firmware else None

        if args.recheck == "all":
            if vendor_prefix or firmware_prefix:
                # 只清除匹配过滤条件的记录
                to_remove = []
                for tid in list(tracker.completed.keys()):
                    if vendor_prefix and not tid.startswith(vendor_prefix):
                        continue
                    if firmware_prefix and firmware_prefix not in tid:
                        continue
                    to_remove.append(tid)
                for tid in to_remove:
                    del tracker.completed[tid]
                tracker.save()
                print(f"[RECHECK] 已清除 {len(to_remove)} 条匹配的完成记录，开始重新分析...")
            else:
                total = len(tracker.completed)
                tracker.completed.clear()
                tracker.save()
                print(f"[RECHECK] 已清除全部 {total} 条完成记录，开始重新分析...")
        else:
            # 只清除匹配 result + vendor/firmware 的记录
            to_remove = [tid for tid, info in tracker.completed.items()
                         if info.get("result") == args.recheck
                         and (not vendor_prefix or tid.startswith(vendor_prefix))
                         and (not firmware_prefix or firmware_prefix in tid)]
            for tid in to_remove:
                del tracker.completed[tid]
            if to_remove:
                tracker.save()
            if not to_remove:
                print(f"[RECHECK] 没有匹配的 '{args.recheck}' 任务")
                return
            print(f"[RECHECK] 已清除 {len(to_remove)} 条 '{args.recheck}' 记录，开始重新分析...")

    # 第一轮执行
    if args.workers >= 2:
        run_batch_parallel(args.vendor, args.firmware, num_workers=args.workers)
    else:
        run_batch(args.vendor, args.firmware)

    # 自动重试：检查是否有失败任务
    if args.auto_retry:
        tracker = ProgressTracker(PROGRESS_FILE)
        failed_ids = tracker.get_failed_task_ids()
        if failed_ids:
            print(f"\n{'=' * 70}")
            print(f"[AUTO-RETRY] 第一轮完成，发现 {len(failed_ids)} 个失败任务")
            print(f"[AUTO-RETRY] 等待 {args.retry_delay} 秒后自动重试...")
            print(f"{'=' * 70}")
            time.sleep(args.retry_delay)

            # 清除失败记录，使其变为待处理
            tracker.clear_all_failed()

            print(f"\n[AUTO-RETRY] 开始第二轮重试...")
            if args.workers >= 2:
                run_batch_parallel(args.vendor, args.firmware, num_workers=args.workers)
            else:
                run_batch(args.vendor, args.firmware)

            # 最终检查
            tracker.load()
            remaining_failed = len(tracker.failed)
            if remaining_failed > 0:
                print(f"\n[AUTO-RETRY] 重试后仍有 {remaining_failed} 个失败任务，请检查 batch_progress.json")
            else:
                print(f"\n[AUTO-RETRY] 全部任务已完成!")
        else:
            print(f"\n[AUTO-RETRY] 无失败任务，无需重试")


if __name__ == "__main__":
    main()
