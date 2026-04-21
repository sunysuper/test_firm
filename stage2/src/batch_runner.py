#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDACMP batch automation script for vulnerability analysis.
Walk Operation Sieve results, group by binary, auto-launch IDA Pro and run analysis.
Each vulnerability gets its own log file; resumable via a progress file.
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

# Project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import config as _config
IDA_EXECUTABLE_PATH = _config.IDA_EXECUTABLE_PATH
MCP_HOST = _config.MCP_HOST
BASE_MCP_PORT = _config.MCP_PORT  # Base port; parallel workers get +i offsets

# ===== Constants (read from config.py rather than hard-coded) =====
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

IDA_STARTUP_WAIT = 60       # Initial wait time for IDA (seconds)
IDA_MCP_CHECK_RETRIES = 20  # MCP connection retries (large binaries need more attempts)
IDA_MCP_CHECK_INTERVAL = 15 # Seconds between retries
AUTO_MCP_SCRIPT = os.path.join(PROJECT_ROOT, "auto_start_mcp.py")
API_COOLDOWN = 10           # Cooldown (seconds) after each vulnerability analysis (protects API rate limits)


# ===== Data structures =====

@dataclass
class VulnerabilityTask:
    """A single vulnerability analysis task"""
    vendor: str
    firmware: str
    sha256: str
    binary_name: str
    binary_linux_path: str
    vuln_type: str          # "cmdi" or "overflow"
    sink_addr: str          # e.g. "0xae38"
    sink_function: str      # e.g. "system"
    rank: float
    trace: list
    sink: dict
    closure_index: int
    reachable_from_main: bool = False
    sanitized: bool = False

    @property
    def binary_key(self) -> str:
        """Unique binary identifier (based on path)"""
        return self.binary_linux_path

    @property
    def task_id(self) -> str:
        """Unique vulnerability task ID"""
        return f"{self.vendor}_{self.firmware}_{self.binary_name}_{self.vuln_type}_{self.sink_addr}"

    @property
    def binary_dir(self) -> str:
        """Extract the binary's directory path inside the firmware (between squashfs-root and the filename)"""
        parts = self.binary_linux_path.split('/')
        sqidx = -1
        for i, p in enumerate(parts):
            if p == 'squashfs-root':
                sqidx = i
                break
        if sqidx >= 0 and sqidx + 2 < len(parts):
            # Path between squashfs-root and the filename, joined with dashes
            dir_parts = parts[sqidx + 1:-1]
            return '-'.join(dir_parts)
        return 'unknown'

    @property
    def log_filename(self) -> str:
        """Generate the log filename"""
        return f"{self.vendor}_{self.firmware}_{self.binary_dir}_{self.binary_name}_{self.vuln_type}_{self.sink_addr}.txt"


@dataclass
class BinaryGroup:
    """Set of vulnerability tasks grouped by binary"""
    binary_linux_path: str
    binary_name: str
    vendor: str
    firmware: str
    tasks: list = field(default_factory=list)
    local_path: Optional[str] = None


# ===== Task scanning =====

def scan_all_tasks(vendor_filter=None, firmware_filter=None) -> list:
    """Scan the results directory and build a list of tasks grouped by binary"""
    binary_groups = {}

    for vendor in os.listdir(RESULTS_ROOT):
        vendor_path = os.path.join(RESULTS_ROOT, vendor)
        if not os.path.isdir(vendor_path):
            continue
        # Skip non-directory entries (e.g. results.csv, symbols.json, vendors.json)
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
                        print(f"  [WARN] failed to parse JSON: {fpath}: {e}")
                        continue

                    closures = data.get("closures", [])
                    binary_name = data.get("name", "unknown")
                    binary_path = data.get("path", "")

                    # If the result file lacks name/path, fall back to env.json
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

    # Dedup: the same sink address may be reached via different traces — keep the highest rank
    for group in binary_groups.values():
        seen = {}
        for task in group.tasks:
            tid = task.task_id
            if tid not in seen or task.rank > seen[tid].rank:
                seen[tid] = task
        group.tasks = list(seen.values())

    # Sort by total rank descending; prioritize the most dangerous binaries
    groups = list(binary_groups.values())
    groups.sort(key=lambda g: sum(t.rank for t in g.tasks), reverse=True)
    return groups


# ===== Path mapping =====

def resolve_local_path(linux_path: str) -> Optional[str]:
    """Convert a path from Sieve results into a local path"""
    if linux_path.startswith(LINUX_PATH_PREFIX):
        relative = linux_path[len(LINUX_PATH_PREFIX):]
        local = os.path.join(FIRMWARE_ROOT, relative)
        if os.path.exists(local):
            return local

    # Fallback: search by filename
    binary_name = os.path.basename(linux_path)
    for root, dirs, files in os.walk(FIRMWARE_ROOT):
        if binary_name in files:
            found = os.path.join(root, binary_name)
            return found

    return None


def get_squashfs_root(linux_path: str) -> Optional[str]:
    """Extract the squashfs-root's local path from a Linux path, used to update FIRMWARE_ROOT"""
    if not linux_path.startswith(LINUX_PATH_PREFIX):
        return None

    relative = linux_path[len(LINUX_PATH_PREFIX):]
    parts = relative.split('/')

    # Locate squashfs-root
    for i, p in enumerate(parts):
        if p == 'squashfs-root':
            sqroot_relative = '/'.join(parts[:i + 1])
            local = os.path.join(FIRMWARE_ROOT, sqroot_relative)
            if os.path.isdir(local):
                return local
            break

    return None


# ===== IDA Pro management =====

class IDAManager:
    """Manages the IDA Pro process lifecycle"""

    def __init__(self, port=None):
        self.ida_path = IDA_EXECUTABLE_PATH
        self.port = port or BASE_MCP_PORT
        self.current_process = None
        self.current_binary = None

    def start_ida(self, binary_path: str) -> bool:
        """Start a new IDA Pro instance"""
        self.stop_ida()

        if not os.path.exists(binary_path):
            print(f"  [ERROR] binary file not found: {binary_path}")
            return False

        # Clean up stale IDA database fragments (left over from a previous crash)
        self._cleanup_stale_idb(binary_path)

        # Clean up IDA crash minidumps (otherwise GUI startup shows a "previously IDA crashed" warning and blocks)
        minidump_dir = "/tmp/ida"
        if os.path.isdir(minidump_dir):
            try:
                removed = 0
                for name in os.listdir(minidump_dir):
                    if name.endswith(".dmp"):
                        os.remove(os.path.join(minidump_dir, name))
                        removed += 1
                if removed:
                    print(f"  [IDA] cleaned up {removed} minidump file(s)")
            except Exception as e:
                print(f"  [WARN] failed to clean minidumps: {e}")

        # Make sure the port is free
        if self._is_port_in_use():
            print(f"  [IDA] port {self.port} in use, waiting for it to free up...")
            for _ in range(6):
                time.sleep(5)
                if not self._is_port_in_use():
                    break
            else:
                print(f"  [ERROR] port {self.port} stays occupied")
                return False

        # Estimate wait time by file size: ~10s per 100KB, at least 60s, at most 600s
        file_size_kb = os.path.getsize(binary_path) / 1024
        wait_time = max(IDA_STARTUP_WAIT, int(file_size_kb / 100 * 10))
        wait_time = min(wait_time, 600)  # Cap at 10 minutes (large files like httpd ~1MB)

        print(f"  [IDA] starting IDA Pro: {os.path.basename(binary_path)} ({file_size_kb:.0f}KB) port={self.port}")
        try:
            # -A: auto-analyze; -S: launch the MCP server after analysis
            cmd = ["xvfb-run", "-a", self.ida_path, "-A", f"-S{AUTO_MCP_SCRIPT}", binary_path]
            env = os.environ.copy()
            env["IDA_MCP_PORT"] = str(self.port)
            env["IDA_MCP_HOST"] = MCP_HOST
            # Capture IDA output to a file rather than a PIPE — a full PIPE buffer
            # causes IDA's write() to block and MCP never starts. File writes grow without blocking.
            self._log_path = f"/tmp/ida_mcp_{self.port}.log"
            self._log_fh = open(self._log_path, "w")
            self.current_process = subprocess.Popen(
                cmd,
                stdout=self._log_fh,
                stderr=subprocess.STDOUT,
                env=env,
                # New process group so stop_ida can killpg the whole tree (xvfb-run + Xvfb + ida).
                # Otherwise terminate only kills the xvfb-run wrapper and the grandchild ida becomes orphaned.
                start_new_session=True,
                **({"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {})
            )
        except Exception as e:
            print(f"  [ERROR] IDA startup failed: {e}")
            return False

        print(f"  [IDA] waiting for IDA analysis to finish ({wait_time}s)...")
        # Wait in chunks, periodically checking that the process is still alive
        elapsed = 0
        ida_exited_early = False
        while elapsed < wait_time:
            chunk = min(15, wait_time - elapsed)
            time.sleep(chunk)
            elapsed += chunk
            if self.current_process and self.current_process.poll() is not None:
                rc = self.current_process.returncode
                ida_exited_early = True
                print(f"  [WARN] IDA process exited early (returncode={rc}); continuing MCP check...")
                break

        # Check the MCP connection
        for attempt in range(IDA_MCP_CHECK_RETRIES):
            if self._check_mcp():
                self.current_binary = binary_path
                print(f"  [IDA] MCP connection succeeded (attempt {attempt + 1})")
                return True
            # If IDA has already exited and this is not the first retry, stop waiting sooner
            if ida_exited_early and attempt >= 3:
                print(f"  [IDA] IDA has exited and MCP is unresponsive; giving up retries")
                break
            print(f"  [IDA] MCP not ready, retry {attempt + 1}/{IDA_MCP_CHECK_RETRIES}...")
            time.sleep(IDA_MCP_CHECK_INTERVAL)

        # Dump diagnostic info on failure
        self._dump_ida_output()
        print("  [ERROR] MCP connection failed after maximum retries")
        self.stop_ida()
        return False

    @staticmethod
    def _cleanup_stale_idb(binary_path: str):
        """Clean up leftover IDA database fragment files (.id0/.id1/.id2/.nam/.til)"""
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
            print(f"  [IDA] cleaned up stale IDB fragments: {', '.join(cleaned)}")

    def _dump_ida_output(self):
        """Print the tail of IDA's log file for diagnostics"""
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
        """Check whether the IDA MCP JSON-RPC server is responding"""
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
        """Check whether the MCP port is occupied"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((MCP_HOST, self.port)) == 0

    def stop_ida(self):
        """Terminate the current IDA Pro instance (and all children under xvfb-run)"""
        if self.current_process:
            pid = self.current_process.pid
            try:
                # killpg the whole process group so the grandchild ida (under xvfb-run) doesn't become an orphan
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


# ===== Progress tracking (resumable) =====

class ProgressTracker:
    """Track completed tasks; supports resume"""

    def __init__(self, progress_file: str):
        self.progress_file = progress_file
        self.completed = {}
        self.failed = {}
        self.load()

    def load(self):
        """Load progress from disk"""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.completed = data.get("completed", {})
                self.failed = data.get("failed", {})
                print(f"  [RESUME] loaded progress: {len(self.completed)} completed, {len(self.failed)} failed")
            except Exception as e:
                print(f"  [WARN] failed to load progress file: {e}")

    def save(self):
        """Persist progress to disk"""
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
        # Clear any stale failure record
        self.failed.pop(task_id, None)
        self.save()

    def mark_failed(self, task_id: str, error: str):
        self.failed[task_id] = {
            "error": error,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.save()

    def clear_all_failed(self):
        """Clear all failure records so those tasks are re-analyzed on the next run"""
        count = len(self.failed)
        self.failed.clear()
        self.save()
        return count

    def get_failed_task_ids(self) -> set:
        """Return the set of task_ids for every failed task"""
        return set(self.failed.keys())

    def clear_by_result(self, result_value: str) -> int:
        """Clear completion records matching the given result so they become pending. Returns the number cleared."""
        to_remove = [tid for tid, info in self.completed.items()
                     if info.get("result") == result_value]
        for tid in to_remove:
            del self.completed[tid]
        if to_remove:
            self.save()
        return len(to_remove)


# ===== Log management =====

def get_log_path(task: VulnerabilityTask) -> str:
    """Build the full path to a vulnerability's log file"""
    log_dir = os.path.join(LOG_ROOT, task.vendor, task.firmware)
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, task.log_filename)


# ===== Dynamic configuration updates =====

def update_config_for_binary(group: BinaryGroup):
    """Update configuration for the current binary (point FIRMWARE_ROOT at the matching squashfs-root)"""
    import config

    sqroot = get_squashfs_root(group.binary_linux_path)
    if sqroot:
        config.update_firmware_root(sqroot)
        print(f"  [CONFIG] FIRMWARE_ROOT -> {sqroot}")
    else:
        print(f"  [WARN] squashfs-root not found; keeping the default FIRMWARE_ROOT")

    # Set the string-search result directory (separated by vendor/firmware)
    string_dir = os.path.join(STRING_SEARCH_DIR, group.vendor, group.firmware)
    os.makedirs(string_dir, exist_ok=True)
    config.update_string_search_dir(string_dir)


# ===== Single-vulnerability analysis =====

def _format_trace_for_log(trace: list, sink: dict) -> str:
    """Format the trace and sink into readable multi-line text"""
    lines = []
    lines.append("Trace Path:")
    for i, entry in enumerate(trace):
        func = entry.get("function", "?")
        addr = entry.get("ins_addr", "?")
        call_str = entry.get("string", "")
        # Truncate overly long BV/MultiValues expressions
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
    Run the full analysis pipeline for a single vulnerability.
    Returns: "controllable", "uncontrollable", or "unknown".
    Also produces a VulnSpec JSON file.
    """
    from analysis_mode.trace_analyze import analyze_trace
    from analysis_mode.vulnerability_analyze import analyze_vulnerability
    from innovation_tool_mode.execute_tools import tools_call
    from interaction import TraceAnalysisAgent, AnalysisAgent, extract_source
    from stage2_output import Stage2OutputManager
    import config as _cfg

    analysis_start = time.time()

    # Write the log header
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

    # ===== PHASE 1: trace analysis =====
    phase1_start = time.time()
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("[PHASE 1] Trace Analysis\n")
        f.write("=" * 60 + "\n")

    print(f"    [TRACE] analyzing {task.sink_function} @ {task.sink_addr}")
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
        f.write(f"[PHASE 1 RESULT] Extracted Source (took {phase1_time:.1f}s)\n")
        f.write(f"{source}\n")
        f.write(f"{'=' * 60}\n\n")

    # ===== PHASE 2: controllability analysis =====
    phase2_start = time.time()
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("[PHASE 2] Vulnerability Controllability Analysis\n")
        f.write("=" * 60 + "\n")

    print(f"    [VULN] controllability analysis...")
    vuln_agent = AnalysisAgent(
        analysis_model=analyze_vulnerability,
        tool_model=tools_call,
        res_file=log_file
    )
    # process() now returns a (conclusion, last_llm_response) tuple
    result, last_llm_response = vuln_agent.process(task.trace, source)
    phase2_time = time.time() - phase2_start
    total_time = time.time() - analysis_start

    # ===== Infer the DEFER reason code (spec 4.2.5.2) =====
    defer_reason = "INSUFFICIENT_EVIDENCE"
    if result == "unknown":
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                log_text = f.read()
            log_lower = log_text.lower()
            if "circuit breaker tripped" in log_lower or "mcp continuously disconnected" in log_lower or "connection error" in log_lower:
                defer_reason = "TOOL_FAILURE"
            elif "max iterations" in log_lower or "max rounds" in log_lower or "budget" in log_lower:
                defer_reason = "BUDGET_EXCEEDED"
            elif "decompile" in log_lower and "fail" in log_lower:
                defer_reason = "DECOMPILE_FAILED"
        except Exception:
            pass

    # ===== Generate the VulnSpec JSON =====
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
        print(f"    [WARN] VulnSpec generation failed: {e}")
        spec_path = None

    # ===== Log footer =====
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


# ===== Dry-run report =====

def print_dry_run_report(groups: list, tracker: ProgressTracker):
    """Scan and show the task list without running the analysis"""
    total_tasks = sum(len(g.tasks) for g in groups)
    pending = sum(1 for g in groups for t in g.tasks if not tracker.is_completed(t.task_id))

    print(f"\n{'=' * 70}")
    print(f"IDACMP batch analysis — dry run report")
    print(f"{'=' * 70}")
    print(f"Binaries:      {len(groups)}")
    print(f"Total vulns:   {total_tasks}")
    print(f"Pending:       {pending}")
    print(f"Completed:     {len(tracker.completed)}")
    print(f"Failed:        {len(tracker.failed)}")

    # Stats by vendor
    vendor_stats = {}
    for g in groups:
        v = g.vendor
        if v not in vendor_stats:
            vendor_stats[v] = {"binaries": 0, "tasks": 0, "pending": 0}
        vendor_stats[v]["binaries"] += 1
        vendor_stats[v]["tasks"] += len(g.tasks)
        vendor_stats[v]["pending"] += sum(1 for t in g.tasks if not tracker.is_completed(t.task_id))

    print(f"\n{'Vendor':<15} {'Binaries':>10} {'Vulns':>8} {'Pending':>10}")
    print("-" * 45)
    for v, s in sorted(vendor_stats.items()):
        print(f"{v:<15} {s['binaries']:>10} {s['tasks']:>8} {s['pending']:>10}")

    # Per-binary details
    print(f"\n{'=' * 70}")
    print("Binary details:")
    print(f"{'=' * 70}")
    for g in groups:
        resolved = resolve_local_path(g.binary_linux_path)
        status = "OK" if resolved else "NOT FOUND"
        pending_count = sum(1 for t in g.tasks if not tracker.is_completed(t.task_id))
        print(f"\n[{g.vendor}/{g.firmware}] {g.binary_name} ({len(g.tasks)} vulns, {pending_count} pending) [{status}]")
        if resolved:
            print(f"  Local: {resolved}")
        else:
            print(f"  Linux: {g.binary_linux_path}")
        for t in g.tasks:
            done = "DONE" if tracker.is_completed(t.task_id) else "PEND"
            print(f"  [{done}] {t.vuln_type} | {t.sink_function} @ {t.sink_addr} | rank={t.rank}")
            print(f"         Log: {t.log_filename}")


def print_results_report(vendor_filter=None, firmware_filter=None):
    """Generate a statistics report of the analysis results; print to terminal and write to file"""
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    tracker = ProgressTracker(PROGRESS_FILE)

    if not tracker.completed and not tracker.failed:
        print("[REPORT] no analysis results yet")
        return

    # Build a task_id → task metadata map
    task_map = {}
    for g in groups:
        for t in g.tasks:
            task_map[t.task_id] = t

    # Bucket by status
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

    # ===== Build the report text =====
    lines = []
    def w(s=""):
        lines.append(s)

    w("=" * 70)
    w("IDACMP vulnerability analysis results report")
    w(f"Generated at: {datetime.datetime.now().isoformat()}")
    w("=" * 70)

    w(f"\n1. Global overview")
    w("-" * 40)
    w(f"  Total analyzed: {total_all}")
    w(f"  Completed:      {total_completed}")
    w(f"    Controllable:     {len(controllable)}")
    w(f"    Uncontrollable:   {len(uncontrollable)}")
    w(f"    Unknown:          {len(unknown)}")
    w(f"  Failed:         {len(failed)}")
    if total_completed > 0:
        ctrl_rate = len(controllable) / total_completed * 100
        w(f"  Controllable rate: {ctrl_rate:.1f}%")

    # ===== Stats by vendor =====
    w(f"\n2. Stats by vendor")
    w("-" * 40)
    vendor_stats = {}
    for task_id, task, _ in controllable + uncontrollable + unknown:
        v = task.vendor if task else task_id.split("_")[0]
        if v not in vendor_stats:
            vendor_stats[v] = {"controllable": 0, "uncontrollable": 0, "unknown": 0}
        result = "controllable" if (task_id, task, _) in controllable else ("uncontrollable" if (task_id, task, _) in uncontrollable else "unknown")

    # Recompute cleanly (the `in` check against tuples above is unreliable)
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

    w(f"  {'Vendor':<12} {'Ctrl':>6} {'Uncon':>6} {'Unkn':>6} {'Fail':>6} {'Total':>6} {'Rate':>8}")
    w(f"  {'-'*58}")
    for v in sorted(vendor_stats.keys()):
        s = vendor_stats[v]
        total_v = s["controllable"] + s["uncontrollable"] + s["unknown"]
        all_v = total_v + s["failed"]
        rate = f"{s['controllable']/total_v*100:.1f}%" if total_v > 0 else "N/A"
        w(f"  {v:<12} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {s['failed']:>6} {all_v:>6} {rate:>8}")

    # ===== Stats by vulnerability type =====
    w(f"\n3. Stats by vulnerability type")
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

    w(f"  {'Type':<12} {'Ctrl':>6} {'Uncon':>6} {'Unkn':>6} {'Total':>6} {'Rate':>8}")
    w(f"  {'-'*50}")
    for vt in sorted(type_stats.keys()):
        s = type_stats[vt]
        total_vt = s["controllable"] + s["uncontrollable"] + s["unknown"]
        rate = f"{s['controllable']/total_vt*100:.1f}%" if total_vt > 0 else "N/A"
        w(f"  {vt:<12} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {total_vt:>6} {rate:>8}")

    # ===== Stats by sink function =====
    w(f"\n4. Stats by sink function")
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

    w(f"  {'Sink function':<20} {'Ctrl':>6} {'Uncon':>6} {'Unkn':>6} {'Total':>6} {'Rate':>8}")
    w(f"  {'-'*58}")
    for sf in sorted(sink_stats.keys(), key=lambda x: -(sink_stats[x]["controllable"] + sink_stats[x]["uncontrollable"] + sink_stats[x]["unknown"])):
        s = sink_stats[sf]
        total_sf = s["controllable"] + s["uncontrollable"] + s["unknown"]
        rate = f"{s['controllable']/total_sf*100:.1f}%" if total_sf > 0 else "N/A"
        w(f"  {sf:<20} {s['controllable']:>6} {s['uncontrollable']:>6} {s['unknown']:>6} {total_sf:>6} {rate:>8}")

    # ===== Controllable vulnerabilities (for manual review) =====
    w(f"\n5. Controllable vulnerabilities ({len(controllable)} total; please review for false positives)")
    w("=" * 70)
    # Group by vendor + firmware
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
                    w(f"    {'':10} Path: {task.binary_dir}/{task.binary_name}")
                    w(f"    {'':10} Log:  {task.log_filename}")
                else:
                    w(f"    {task_id}")

    # ===== Unknown-result list =====
    if unknown:
        w(f"\n6. Unknown results ({len(unknown)} total; please review manually)")
        w("=" * 70)
        for task_id, task, ts in unknown:
            if task:
                w(f"  {task.vendor}/{task.firmware}: {task.vuln_type} {task.sink_function}@{task.sink_addr} binary={task.binary_name}")
                w(f"    Log: {task.log_filename}")
            else:
                w(f"  {task_id}")

    # ===== Failed tasks =====
    if failed:
        section = "7" if unknown else "6"
        w(f"\n{section}. Failed tasks ({len(failed)} total)")
        w("=" * 70)
        # Group by error type
        error_groups = {}
        for task_id, task, err, ts in failed:
            short_err = err[:60] if len(err) > 60 else err
            error_groups.setdefault(short_err, []).append((task_id, task))

        for err, tasks in sorted(error_groups.items(), key=lambda x: -len(x[1])):
            w(f"\n  Error: {err} ({len(tasks)} task(s))")
            for task_id, task in tasks:
                name = f"{task.binary_name} ({task.vuln_type} {task.sink_function}@{task.sink_addr})" if task else task_id
                w(f"    - {name}")

    w(f"\n{'=' * 70}")

    # Print to terminal
    report_text = "\n".join(lines)
    print(report_text)

    # Save to file
    report_file = os.path.join(LOG_ROOT, "analysis_results_report.txt")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\nReport saved to: {report_file}")


# ===== Main execution loop =====

def run_batch(vendor_filter=None, firmware_filter=None):
    """Main batch execution entry point"""
    print("=" * 70)
    print("IDACMP batch vulnerability analysis")
    print(f"Started at: {datetime.datetime.now().isoformat()}")
    if vendor_filter:
        print(f"Vendor filter: {vendor_filter}")
    if firmware_filter:
        print(f"Firmware filter: {firmware_filter}")
    print("=" * 70)

    # Step 1: scan tasks
    print("\n[SCAN] scanning results directory...")
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    total_tasks = sum(len(g.tasks) for g in groups)
    print(f"[SCAN] found {len(groups)} binaries, {total_tasks} high-risk vulnerabilities")

    if not groups:
        print("[DONE] no vulnerabilities to analyze")
        return

    # Step 2: resolve local paths
    print("\n[PATH] resolving local binary paths...")
    valid_groups = []
    skipped_binaries = 0
    for group in groups:
        local = resolve_local_path(group.binary_linux_path)
        if local:
            group.local_path = local
            valid_groups.append(group)
        else:
            skipped_binaries += 1
            print(f"  [SKIP] file not found: {group.binary_name} ({group.vendor}/{group.firmware})")

    valid_tasks = sum(len(g.tasks) for g in valid_groups)
    print(f"[PATH] {len(valid_groups)} binaries available ({valid_tasks} vulns), "
          f"{skipped_binaries} skipped")

    # Step 3: load progress
    tracker = ProgressTracker(PROGRESS_FILE)
    remaining = sum(1 for g in valid_groups for t in g.tasks if not tracker.is_completed(t.task_id))
    print(f"\n[RESUME] {remaining} tasks remaining (of {valid_tasks})")

    if remaining == 0:
        print("[DONE] all tasks complete!")
        return

    # Step 4: run the analysis
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
            print(f"  Vendor: {group.vendor} | Firmware: {group.firmware}")
            print(f"  Path:   {group.local_path}")
            print(f"  Tasks:  {len(pending_tasks)} pending / {len(group.tasks)} total")
            print(f"{'=' * 60}")

            # Update configuration
            update_config_for_binary(group)

            # Clear the MCP query cache (we're switching binaries)
            try:
                from innovation_tool_mode.tools import clear_cache
                clear_cache()
            except ImportError:
                pass

            # Start IDA
            if not ida.start_ida(group.local_path):
                print(f"  [ERROR] IDA startup failed; skipping {group.binary_name}")
                for task in pending_tasks:
                    tracker.mark_failed(task.task_id, "IDA startup failed")
                    stats["failed"] += 1
                continue

            # Analyze each vulnerability
            for t_idx, task in enumerate(pending_tasks):
                log_file = get_log_path(task)
                print(f"\n  --- Vulnerability {t_idx + 1}/{len(pending_tasks)} ---")
                print(f"  Type: {task.vuln_type} | Sink: {task.sink_function} @ {task.sink_addr} | Rank: {task.rank}")
                print(f"  Log:  {task.log_filename}")

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

                    # Retriable errors: 429 rate limit, 5xx server errors, connection errors
                    is_rate_limit = "429" in str(e) or "rate_limit" in str(e).lower()
                    is_server_error = any(code in str(e) for code in ["500", "502", "503", "504", "Bad gateway", "bad gateway"])
                    is_connection_error = "APIConnectionError" in type(e).__name__ or "Connection error" in str(e) or "ConnectionError" in type(e).__name__

                    if is_rate_limit or is_server_error or is_connection_error:
                        wait_time = 30 if is_rate_limit else 60
                        max_retries = 2
                        reason = "API rate limit" if is_rate_limit else ("connection error" if is_connection_error else "server error (5xx)")

                        for retry in range(max_retries):
                            print(f"  [RETRY] {reason}; waiting {wait_time}s before retry ({retry+1}/{max_retries})...")
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
                                print(f"  [RESULT] retry succeeded: {result}")
                                time.sleep(API_COOLDOWN)
                                break
                            except Exception as e2:
                                error_msg = f"{type(e2).__name__}: {str(e2)}"
                                print(f"  [ERROR] retry {retry+1} failed: {error_msg}")
                                wait_time = min(wait_time * 2, 120)  # Exponential backoff, capped at 2 minutes
                        else:
                            # All retries failed
                            tracker.mark_failed(task.task_id, error_msg)
                            stats["failed"] += 1
                            continue

                        continue  # retry succeeded — skip the failure handling below

                    tracker.mark_failed(task.task_id, error_msg)
                    stats["failed"] += 1

                    # Write the error to the log file
                    try:
                        with open(log_file, "a", encoding="utf-8") as f:
                            f.write(f"\n[ERROR] {error_msg}\n")
                            f.write(traceback.format_exc())
                    except:
                        pass

            # Done with the current binary; shut down IDA
            ida.stop_ida()
            print(f"\n  [DONE] {group.binary_name} analysis finished")

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] user interrupt; shutting down safely...")
        ida.stop_ida()
    finally:
        ida.stop_ida()

    # Step 5: summary report
    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"Batch analysis finished")
    print(f"{'=' * 70}")
    print(f"Elapsed:       {elapsed / 3600:.1f} h ({elapsed:.0f}s)")
    print(f"Completed:     {stats['completed']}")
    print(f"  Controllable:    {stats['controllable']}")
    print(f"  Uncontrollable:  {stats['uncontrollable']}")
    print(f"  Unknown:         {stats['unknown']}")
    print(f"Failed:        {stats['failed']}")
    print(f"Skipped:       {stats['skipped']}")
    print(f"Progress file: {PROGRESS_FILE}")
    print(f"Log directory: {LOG_ROOT}")
    print(f"{'=' * 70}")


# ===== Multi-process parallel analysis =====

def _analyze_with_retry(task, log_file):
    """Run a single vulnerability analysis with 429/5xx retry logic. Returns (status, result_or_error)."""
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
            reason = "API rate limit" if is_rate_limit else ("connection error" if is_connection_error else "server error")

            for retry in range(max_retries):
                print(f"  [RETRY] {reason}; waiting {wait_time}s before retry ({retry+1}/{max_retries})...")
                time.sleep(wait_time)
                try:
                    result = analyze_single_vulnerability(task, log_file)
                    return ("completed", result)
                except Exception as e2:
                    error_msg = f"{type(e2).__name__}: {str(e2)}"
                    print(f"  [ERROR] retry {retry+1} failed: {error_msg}")
                    wait_time = min(wait_time * 2, 120)

        # Write the error to the log file
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n[ERROR] {error_msg}\n")
                f.write(traceback.format_exc())
        except:
            pass
        return ("failed", error_msg)


def worker_process(worker_id, port, task_queue, result_queue):
    """
    Worker process entry: pull binary groups from the queue and analyze their vulnerabilities one by one.
    Each worker has its own Python module-global namespace.
    """
    import config
    config.update_mcp_port(port)

    prefix = f"[W{worker_id}]"
    print(f"{prefix} worker started, MCP port={port}")

    ida = IDAManager(port=port)

    while True:
        try:
            item = task_queue.get(timeout=5)
        except:
            # Queue empty and timed out — check whether more tasks exist
            if task_queue.empty():
                break
            continue

        if item is None:
            # Poison-pill sentinel — exit
            break

        group, pending_task_ids = item
        pending_tasks = [t for t in group.tasks if t.task_id in pending_task_ids]

        print(f"\n{prefix} {'=' * 50}")
        print(f"{prefix} binary: {group.binary_name} ({group.vendor}/{group.firmware})")
        print(f"{prefix} tasks: {len(pending_tasks)}")
        print(f"{prefix} {'=' * 50}")

        # Update this worker's configuration
        update_config_for_binary(group)

        # Clear the MCP query cache (we're switching binaries)
        try:
            from innovation_tool_mode.tools import clear_cache
            clear_cache()
        except ImportError:
            pass

        # Start IDA
        if not ida.start_ida(group.local_path):
            print(f"{prefix} [ERROR] IDA startup failed; skipping {group.binary_name}")
            for task in pending_tasks:
                result_queue.put((task.task_id, "failed", "IDA startup failed"))
            continue

        # Analyze each vulnerability
        for t_idx, task in enumerate(pending_tasks):
            log_file = get_log_path(task)
            print(f"\n{prefix} --- vulnerability {t_idx+1}/{len(pending_tasks)} ---")
            print(f"{prefix} {task.vuln_type} | {task.sink_function} @ {task.sink_addr} | rank={task.rank}")

            status, result = _analyze_with_retry(task, log_file)
            result_queue.put((task.task_id, status, result))
            print(f"{prefix} [RESULT] {status}: {result}")

            if status == "completed":
                time.sleep(API_COOLDOWN)

        # Done with this binary
        ida.stop_ida()
        print(f"{prefix} [DONE] {group.binary_name} analysis finished")

    ida.stop_ida()
    print(f"{prefix} worker exiting")


def run_batch_parallel(vendor_filter=None, firmware_filter=None, num_workers=2):
    """Multi-process parallel batch entry point"""
    print("=" * 70)
    print(f"IDACMP batch vulnerability analysis (parallel mode, {num_workers} workers)")
    print(f"Started at: {datetime.datetime.now().isoformat()}")
    if vendor_filter:
        print(f"Vendor filter: {vendor_filter}")
    if firmware_filter:
        print(f"Firmware filter: {firmware_filter}")
    print("=" * 70)

    # Step 1: scan tasks
    print("\n[SCAN] scanning results directory...")
    groups = scan_all_tasks(vendor_filter, firmware_filter)
    total_tasks = sum(len(g.tasks) for g in groups)
    print(f"[SCAN] found {len(groups)} binaries, {total_tasks} high-risk vulnerabilities")

    if not groups:
        print("[DONE] no vulnerabilities to analyze")
        return

    # Step 2: resolve local paths
    print("\n[PATH] resolving local binary paths...")
    valid_groups = []
    for group in groups:
        local = resolve_local_path(group.binary_linux_path)
        if local:
            group.local_path = local
            valid_groups.append(group)
        else:
            print(f"  [SKIP] file not found: {group.binary_name} ({group.vendor}/{group.firmware})")

    valid_tasks = sum(len(g.tasks) for g in valid_groups)
    print(f"[PATH] {len(valid_groups)} binaries available ({valid_tasks} vulns)")

    # Step 3: load progress, filter out completed tasks
    tracker = ProgressTracker(PROGRESS_FILE)

    pending_groups = []
    for group in valid_groups:
        pending_ids = set(t.task_id for t in group.tasks if not tracker.is_completed(t.task_id))
        if pending_ids:
            pending_groups.append((group, pending_ids))

    remaining = sum(len(ids) for _, ids in pending_groups)
    print(f"\n[RESUME] {remaining} tasks remaining (of {valid_tasks})")

    if remaining == 0:
        print("[DONE] all tasks complete!")
        return

    # Step 4: create queues and start workers
    task_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()

    for group, pending_ids in pending_groups:
        task_queue.put((group, pending_ids))

    # Feed poison-pill sentinels
    for _ in range(num_workers):
        task_queue.put(None)

    # Start worker processes
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
        print(f"[MAIN] worker {i} started (PID={p.pid}, port={port})")

    # Step 5: the main process collects results
    stats = {
        "completed": 0, "failed": 0,
        "controllable": 0, "uncontrollable": 0, "unknown": 0,
    }
    start_time = time.time()

    try:
        while True:
            # Check whether all workers have exited
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
            print(f"[MAIN] progress: {done}/{remaining} (ok:{stats['completed']} fail:{stats['failed']})")

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] user interrupt; terminating all workers...")
        for w in workers:
            w.terminate()

    # Wait for all workers to exit
    for w in workers:
        w.join(timeout=30)
        if w.is_alive():
            w.kill()

    # Step 6: summary report
    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"Batch analysis finished (parallel mode, {num_workers} workers)")
    print(f"{'=' * 70}")
    print(f"Elapsed:       {elapsed / 3600:.1f} h ({elapsed:.0f}s)")
    print(f"Completed:     {stats['completed']}")
    print(f"  Controllable:    {stats['controllable']}")
    print(f"  Uncontrollable:  {stats['uncontrollable']}")
    print(f"  Unknown:         {stats['unknown']}")
    print(f"Failed:        {stats['failed']}")
    print(f"Progress file: {PROGRESS_FILE}")
    print(f"Log directory: {LOG_ROOT}")
    print(f"{'=' * 70}")

def main():
    parser = argparse.ArgumentParser(
        description="IDACMP batch vulnerability analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python batch_runner.py --dry-run              # Scan and list tasks only
  python batch_runner.py --vendor Tenda         # Only process Tenda (single-process)
  python batch_runner.py --workers 2            # Run 2 IDA instances in parallel
  python batch_runner.py --workers 3 --vendor Tenda  # 3-way parallelism + vendor filter
  python batch_runner.py --reset-progress       # Wipe progress and start over
  python batch_runner.py --retry-failed         # Retry only previously failed tasks
  python batch_runner.py --report               # Emit the analysis results statistics report
  python batch_runner.py --recheck controllable # Re-analyze every "controllable" result
  python batch_runner.py --recheck controllable --vendor Tenda  # Re-analyze Tenda controllable results only
  python batch_runner.py --task Tenda_..._httpd_cmdi_0xad398   # Re-analyze a single task
        """
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="scan and list tasks only; do not run analysis")
    parser.add_argument("--vendor", type=str,
                        help="only process the specified vendor (e.g. Tenda, d-link, NETGEAR, TP_Link)")
    parser.add_argument("--firmware", type=str,
                        help="only process the specified firmware (must be combined with --vendor)")
    parser.add_argument("--workers", type=int, default=1,
                        help="number of parallel workers (default 1 = serial, >=2 enables multi-process)")
    parser.add_argument("--reset-progress", action="store_true",
                        help="wipe the progress file and start over")
    parser.add_argument("--retry-failed", action="store_true",
                        help="retry only previously failed tasks")
    parser.add_argument("--report", action="store_true",
                        help="emit the analysis results statistics report (includes controllable list for FP review)")
    parser.add_argument("--recheck", type=str, metavar="RESULT",
                        choices=["controllable", "uncontrollable", "unknown", "all"],
                        help="re-analyze tasks with the given result (controllable/uncontrollable/unknown/all)")
    parser.add_argument("--task", type=str, metavar="TASK_ID",
                        help="re-analyze a single task (task_id, e.g. Tenda_US_AC15..._httpd_cmdi_0xad398)")
    parser.add_argument("--auto-retry", action="store_true",
                        help="after the first round, automatically retry failed tasks (default: wait 120s then retry)")
    parser.add_argument("--retry-delay", type=int, default=120,
                        help="seconds to wait before auto-retry (default 120s; pairs with --auto-retry)")

    args = parser.parse_args()

    if args.reset_progress and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
        print("[RESET] progress cleared")

    if args.dry_run:
        groups = scan_all_tasks(args.vendor, args.firmware)
        tracker = ProgressTracker(PROGRESS_FILE)
        print_dry_run_report(groups, tracker)
        return

    if args.report:
        print_results_report(args.vendor, args.firmware)
        return

    # --task: analyze exactly this one task and exit
    if args.task:
        tracker = ProgressTracker(PROGRESS_FILE)
        tid = args.task
        # Clear old records
        if tid in tracker.completed:
            old = tracker.completed.pop(tid)
            tracker.save()
            print(f"[RECHECK] cleared task '{tid}' (previous result: {old.get('result', '?')})")
        elif tid in tracker.failed:
            tracker.failed.pop(tid)
            tracker.save()
            print(f"[RECHECK] cleared failed task '{tid}'")

        # Scan to locate the task
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
            print(f"[ERROR] task '{tid}' not found")
            print(f"  Hint: use --dry-run to view all available task_ids")
            return

        # Resolve local path
        local = resolve_local_path(target_group.binary_linux_path)
        if not local:
            print(f"[ERROR] binary file not found: {target_group.binary_linux_path}")
            return
        target_group.local_path = local

        # Update config, start IDA, analyze, exit
        update_config_for_binary(target_group)

        # Clear the MCP query cache
        try:
            from innovation_tool_mode.tools import clear_cache
            clear_cache()
        except ImportError:
            pass

        ida = IDAManager()
        try:
            if not ida.start_ida(local):
                print(f"[ERROR] IDA startup failed")
                tracker.mark_failed(tid, "IDA startup failed")
                return

            log_file = get_log_path(target_task)
            print(f"\n[TASK] {target_task.vuln_type} | {target_task.sink_function} @ {target_task.sink_addr}")
            print(f"[TASK] log: {log_file}")

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

    # --retry-failed: wipe failure records, then run normally
    if args.retry_failed:
        tracker = ProgressTracker(PROGRESS_FILE)
        failed_ids = tracker.get_failed_task_ids()
        if not failed_ids:
            print("[RETRY] no failed tasks to retry")
            return
        count = tracker.clear_all_failed()
        print(f"[RETRY] cleared {count} failure record(s), retrying...")

    # --recheck: clear the selected results, then run normally
    if args.recheck:
        tracker = ProgressTracker(PROGRESS_FILE)
        # If --vendor/--firmware is set, only clear matching tasks
        vendor_prefix = f"{args.vendor}_" if args.vendor else None
        firmware_prefix = f"{args.firmware}_" if args.firmware else None

        if args.recheck == "all":
            if vendor_prefix or firmware_prefix:
                # Only clear records matching the filter
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
                print(f"[RECHECK] cleared {len(to_remove)} matching completion record(s); re-analyzing...")
            else:
                total = len(tracker.completed)
                tracker.completed.clear()
                tracker.save()
                print(f"[RECHECK] cleared all {total} completion record(s); re-analyzing...")
        else:
            # Only clear records matching result + vendor/firmware
            to_remove = [tid for tid, info in tracker.completed.items()
                         if info.get("result") == args.recheck
                         and (not vendor_prefix or tid.startswith(vendor_prefix))
                         and (not firmware_prefix or firmware_prefix in tid)]
            for tid in to_remove:
                del tracker.completed[tid]
            if to_remove:
                tracker.save()
            if not to_remove:
                print(f"[RECHECK] no matching '{args.recheck}' tasks")
                return
            print(f"[RECHECK] cleared {len(to_remove)} '{args.recheck}' record(s); re-analyzing...")

    # First pass
    if args.workers >= 2:
        run_batch_parallel(args.vendor, args.firmware, num_workers=args.workers)
    else:
        run_batch(args.vendor, args.firmware)

    # Auto-retry: check for failed tasks
    if args.auto_retry:
        tracker = ProgressTracker(PROGRESS_FILE)
        failed_ids = tracker.get_failed_task_ids()
        if failed_ids:
            print(f"\n{'=' * 70}")
            print(f"[AUTO-RETRY] first pass finished; found {len(failed_ids)} failed task(s)")
            print(f"[AUTO-RETRY] waiting {args.retry_delay}s before auto-retry...")
            print(f"{'=' * 70}")
            time.sleep(args.retry_delay)

            # Clear failure records so they become pending
            tracker.clear_all_failed()

            print(f"\n[AUTO-RETRY] starting second pass...")
            if args.workers >= 2:
                run_batch_parallel(args.vendor, args.firmware, num_workers=args.workers)
            else:
                run_batch(args.vendor, args.firmware)

            # Final check
            tracker.load()
            remaining_failed = len(tracker.failed)
            if remaining_failed > 0:
                print(f"\n[AUTO-RETRY] {remaining_failed} task(s) still failing after retry; check batch_progress.json")
            else:
                print(f"\n[AUTO-RETRY] all tasks complete!")
        else:
            print(f"\n[AUTO-RETRY] no failed tasks; nothing to retry")


if __name__ == "__main__":
    main()
