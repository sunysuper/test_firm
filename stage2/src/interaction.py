from innovation_tool_mode.execute_tools import tools_call
from analysis_mode.trace_analyze import analyze_trace
from analysis_mode.vulnerability_analyze import analyze_vulnerability
import os
import json
from string_database.search_string import occurrence_of_string
import re
from config import LOG_FILE_PATH, SIEVE_RESULTS_ROOT
from auto_loader import load_binary_for_analysis, get_current_binary_info

def extract_search_string(analysis_response: str) -> list[str]:
    # (['"]) 捕获单/双引号，(.*?) 惰性匹配引号内部内容，\1 保证闭合引号同类型
    pattern = re.compile(r"""occurrence:\s*   # occurrence: 及空白
                             (['"])           # 开引号，捕获到 group(1)
                             (.*?)            # 惰性匹配中间内容，捕获到 group(2)
                             \1               # 和 group(1) 相同的闭合引号
                          """, re.VERBOSE)
    cleaned = pattern.sub("", analysis_response)
    return [m.group(2) for m in pattern.finditer(analysis_response)], cleaned

def extract_source(response):
        if "<think>" in response and "</think>" in response:
            return response.split("</think>")[-1].strip()
        return response.strip()


def _extract_tool_result_content(tool_result):
    """从 tools_call 返回值中提取可读文本"""
    if isinstance(tool_result, dict):
        parts = []
        # 提取最终响应
        final = tool_result.get("final_response", "")
        if final:
            parts.append(str(final))
        # 提取具体工具执行结果
        all_results = tool_result.get("all_results", {})
        if isinstance(all_results, dict) and all_results:
            for tool_name, result in all_results.items():
                result_str = str(result) if result is not None else ""
                if result_str and not result_str.startswith("Error"):
                    parts.append(f"工具 {tool_name} 的结果:\n{result_str}")
        return "\n\n".join(parts) if parts else str(tool_result)
    return str(tool_result)


def _check_conclusion(analysis_result: str) -> str:
    """
    用结构化标记判断分析结论。
    优先匹配 'Conclusion:' 前缀，避免中间分析文本中的误判。
    返回: "controllable", "uncontrollable", 或 None
    """
    text = analysis_result.lower()

    # 如果文本包含 "additional information"，说明模型还在请求数据，不应判定为结论
    if "additional information" in text:
        return None

    # 优先匹配 "Conclusion: Not Controllable" / "Conclusion: Controllable"
    conclusion_match = re.search(r'conclusion\s*:\s*(not\s+controllable|controllable)', text)
    if conclusion_match:
        if "not" in conclusion_match.group(1):
            return "uncontrollable"
        return "controllable"

    # 回退：匹配断言句式，排除疑问/假设上下文
    if re.search(r'\b(?:is|are)\s+not\s+controllable\b(?!\s*(?:or|\?))', text):
        return "uncontrollable"
    if re.search(r'\b(?:is|are)\s+controllable\b(?!\s*(?:or|\?))', text):
        return "controllable"

    return None


class AnalysisAgent:
    """判断漏洞的可控性（是否可以被攻击者利用）。
    analyze_vulnerability 内部已处理工具调用循环，此处不再重复调用。"""
    def __init__(self, analysis_model, tool_model, res_file):
        self.analysis_model = analysis_model
        self.tool_model = tool_model
        self.res_file = res_file

    def process(self, trace, sink):
        """返回 (conclusion, last_llm_response) 元组。
        conclusion: "controllable" / "uncontrollable" / "unknown"
        last_llm_response: 最后一轮 LLM 的完整响应文本（含 VULN_SPEC 块）"""
        history_messages = [{"role": "user", "content": f"trace: {trace}, sink: {sink}"}]
        max_iterations = 15
        iteration = 0
        analysis_result = ""
        while iteration < max_iterations:
            iteration += 1
            # analyze_vulnerability 内部已有工具调用循环，返回最终分析结论
            analysis_result = self.analysis_model(history_messages, self.res_file)

            # 用结构化标记判断结论
            conclusion = _check_conclusion(analysis_result)
            if conclusion:
                if conclusion == "controllable":
                    print("Analysis is clear, no further action taken.")
                return conclusion, analysis_result

            # 仍含 "additional information"：说明内部循环耗尽仍未解决，
            # 将结果反馈给分析模型做最后一轮判断
            if "additional information" in analysis_result.lower():
                history_messages.append({"role": "assistant", "content": analysis_result})
                history_messages.append({"role": "user", "content":
                    "工具调用已达上限，无法获取更多信息。请基于目前已有的全部信息给出最终结论，格式为 Conclusion: Controllable 或 Conclusion: Not Controllable。同时请输出 VULN_SPEC_START...VULN_SPEC_END 结构化信息块。"})
                continue

            # 其他情况（无结论也无额外请求），再给一次机会
            history_messages.append({"role": "assistant", "content": analysis_result})
            history_messages.append({"role": "user", "content":
                "请给出最终结论，格式为 Conclusion: Controllable 或 Conclusion: Not Controllable。同时请输出 VULN_SPEC_START...VULN_SPEC_END 结构化信息块。"})

        # 超过最大迭代次数
        print(f"[AnalysisAgent] 达到最大迭代次数({max_iterations})，结束分析")
        conclusion = _check_conclusion(analysis_result)
        return (conclusion if conclusion else "unknown"), analysis_result


class TraceAnalysisAgent:
    """分析调用轨迹，修正和验证从外部工具获得的trace信息。
    analyze_trace 内部已处理工具调用循环，此处直接返回结果。"""
    def __init__(self, analysis_model, tool_model, res_file):
        self.analysis_model = analysis_model
        self.tool_model = tool_model
        self.res_file = res_file

    def process(self, trace, sink):
        history_messages = [{"role": "user", "content": f"trace: {trace}, sink: {sink}"}]
        # analyze_trace 内部已有完整的工具调用循环（最多5轮），直接返回最终结果
        analysis_result = self.analysis_model(history_messages, self.res_file)
        return analysis_result

def find_cmdi_results_files(root_dir):
    cmdi_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            '''改为cmdi_results.json'''
            if file == "overflow_results.json":
                cmdi_files.append(os.path.join(root, file))
    return cmdi_files
                          
def extract_sink_trace():
    root = SIEVE_RESULTS_ROOT
    cmdi_files = find_cmdi_results_files(root)
    results = {}
    for file_path in cmdi_files:
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
                binary = data["name"]
                binary_path = data.get("path", "")  # 获取二进制文件路径
                results[binary] = {
                    "path": binary_path,
                    "vulnerabilities": []
                }
                if "closures" in data:
                    closure = data["closures"]
                    for item in closure:
                        if item["rank"] >= 7.0:
                            sink = item["sink"]
                            trace = item["trace"]
                            results[binary]["vulnerabilities"].append({"trace":trace, "sink":sink})    
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {file_path}: {e}")
    return results

if __name__ == "__main__":
    results = extract_sink_trace()
    res_file = LOG_FILE_PATH
    print("找到的二进制文件和漏洞：")
    for binary, data in results.items():
        if data["vulnerabilities"]:
            print(f"- {binary}: {len(data['vulnerabilities'])} 个高危漏洞")
    
    for binary, data in results.items():
        if data["vulnerabilities"]:
            print(f"\n{'='*60}")
            print(f"开始分析二进制文件: {binary}")
            print(f"文件路径: {data['path']}")
            print(f"漏洞数量: {len(data['vulnerabilities'])}")
            print(f"{'='*60}")
            
            # 自动加载对应的二进制文件
            print(f"\n[自动加载] 正在加载二进制文件: {binary}")
            load_success = load_binary_for_analysis(binary, data["path"])
            
            if not load_success:
                print(f"[错误] 无法加载二进制文件 {binary}，跳过该文件的分析")
                continue
            
            # 显示当前加载的文件信息
            current_info = get_current_binary_info()
            print(f"[成功] 当前加载的文件: {current_info['name']}")
            print(f"[路径] {current_info['path']}")
            
            # 用户确认是否继续分析
            res = input(f"\n是否继续分析 {binary}? (直接回车继续，输入'skip'跳过): ")
            if res.lower() == 'skip':
                continue
            
            # 分析每个漏洞
            for i, item in enumerate(data["vulnerabilities"]):
                print(f"\n--- 分析漏洞 {i+1}/{len(data['vulnerabilities'])} ---")
                trace = item["trace"]
                sink = item["sink"]
                
                # 显示漏洞信息
                print(f"Sink地址: {sink.get('ins_addr', 'N/A')}")
                print(f"Sink函数: {sink.get('function', 'N/A')}")
                if trace:
                    print(f"Trace起始地址: {trace[0].get('ins_addr', 'N/A')}")
                    print(f"Trace起始函数: {trace[0].get('function', 'N/A')}")
                
                # 过滤特定地址（保留原有逻辑）
                if "0xb54c" in sink["ins_addr"] or "0xb574" in sink["ins_addr"] or "0xb96c" in sink["ins_addr"] or "0xaf08" in sink["ins_addr"] or "0xb5a0" in sink["ins_addr"] or "0x17b08" in sink["ins_addr"] or "0x1ae64" in sink["ins_addr"] or "0xc2a8" in sink["ins_addr"] or "0x102a8" in sink["ins_addr"] or "0x17ea0" in sink["ins_addr"]:
                    print("跳过特定地址的漏洞")
                    continue
                
                # 记录到日志文件
                with open(res_file, "+a", encoding='utf-8') as f:
                    f.write(f"trace:{trace}, sink:{sink}\n")
                
                # 执行trace分析
                print("开始trace分析...")
                trace_agent = TraceAnalysisAgent(analysis_model=analyze_trace, tool_model=tools_call, res_file=res_file)
                source = extract_source(trace_agent.process(trace, sink))
                print("Extracted Source:", source)
        
                # 执行可控性分析
                print("开始可控性分析...")
                agent = AnalysisAgent(analysis_model=analyze_vulnerability, tool_model=tools_call, res_file=res_file)
                if_controllable, _llm_response = agent.process(trace, source)
                print("Final Response:", if_controllable)
            
            print(f"\n{binary} 的所有漏洞分析完成")
    
    print("\n所有二进制文件分析完成!")