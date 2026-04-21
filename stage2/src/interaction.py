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
    # (['"]) captures a single or double quote; (.*?) lazily matches the content inside;
    # \1 ensures the closing quote matches the same type as the opening quote.
    pattern = re.compile(r"""occurrence:\s*   # 'occurrence:' and whitespace
                             (['"])           # opening quote, captured into group(1)
                             (.*?)            # lazy match on the enclosed content, captured into group(2)
                             \1               # closing quote that must match group(1)
                          """, re.VERBOSE)
    cleaned = pattern.sub("", analysis_response)
    return [m.group(2) for m in pattern.finditer(analysis_response)], cleaned

def extract_source(response):
        if "<think>" in response and "</think>" in response:
            return response.split("</think>")[-1].strip()
        return response.strip()


def _extract_tool_result_content(tool_result):
    """Extract human-readable text from the tools_call return value"""
    if isinstance(tool_result, dict):
        parts = []
        # Extract the final response
        final = tool_result.get("final_response", "")
        if final:
            parts.append(str(final))
        # Extract individual tool execution results
        all_results = tool_result.get("all_results", {})
        if isinstance(all_results, dict) and all_results:
            for tool_name, result in all_results.items():
                result_str = str(result) if result is not None else ""
                if result_str and not result_str.startswith("Error"):
                    parts.append(f"Result of tool {tool_name}:\n{result_str}")
        return "\n\n".join(parts) if parts else str(tool_result)
    return str(tool_result)


def _check_conclusion(analysis_result: str) -> str:
    """
    Decide the conclusion from structured markers.
    Match the 'Conclusion:' prefix first, to avoid false positives from mid-analysis text.
    Returns: "controllable", "uncontrollable", or None
    """
    text = analysis_result.lower()

    # If the text contains "additional information", the model is still requesting data — not a conclusion
    if "additional information" in text:
        return None

    # Prefer matching "Conclusion: Not Controllable" / "Conclusion: Controllable"
    conclusion_match = re.search(r'conclusion\s*:\s*(not\s+controllable|controllable)', text)
    if conclusion_match:
        if "not" in conclusion_match.group(1):
            return "uncontrollable"
        return "controllable"

    # Fallback: match assertive phrasing, excluding questions / hypothetical contexts
    if re.search(r'\b(?:is|are)\s+not\s+controllable\b(?!\s*(?:or|\?))', text):
        return "uncontrollable"
    if re.search(r'\b(?:is|are)\s+controllable\b(?!\s*(?:or|\?))', text):
        return "controllable"

    return None


class AnalysisAgent:
    """Decide whether a vulnerability is controllable (i.e. exploitable by an attacker).
    analyze_vulnerability already runs the internal tool-call loop, so no extra invocation is needed here."""
    def __init__(self, analysis_model, tool_model, res_file):
        self.analysis_model = analysis_model
        self.tool_model = tool_model
        self.res_file = res_file

    def process(self, trace, sink):
        """Returns a (conclusion, last_llm_response) tuple.
        conclusion: "controllable" / "uncontrollable" / "unknown"
        last_llm_response: full text of the final LLM round (includes the VULN_SPEC block)"""
        history_messages = [{"role": "user", "content": f"trace: {trace}, sink: {sink}"}]
        max_iterations = 15
        iteration = 0
        analysis_result = ""
        while iteration < max_iterations:
            iteration += 1
            # analyze_vulnerability has its own tool-call loop and returns the final analysis conclusion
            analysis_result = self.analysis_model(history_messages, self.res_file)

            # Decide the conclusion from structured markers
            conclusion = _check_conclusion(analysis_result)
            if conclusion:
                if conclusion == "controllable":
                    print("Analysis is clear, no further action taken.")
                return conclusion, analysis_result

            # Still contains "additional information": the inner loop ran out before resolving —
            # send the result back to the analysis model for one last round
            if "additional information" in analysis_result.lower():
                history_messages.append({"role": "assistant", "content": analysis_result})
                history_messages.append({"role": "user", "content":
                    "The tool-call budget is exhausted and no more information can be fetched. Based on everything you have so far, give a final conclusion formatted as 'Conclusion: Controllable' or 'Conclusion: Not Controllable'. Also emit the structured VULN_SPEC_START...VULN_SPEC_END block."})
                continue

            # Otherwise (no conclusion, no further request), give one more chance
            history_messages.append({"role": "assistant", "content": analysis_result})
            history_messages.append({"role": "user", "content":
                "Please give a final conclusion formatted as 'Conclusion: Controllable' or 'Conclusion: Not Controllable'. Also emit the structured VULN_SPEC_START...VULN_SPEC_END block."})

        # Max iterations exceeded
        print(f"[AnalysisAgent] max iterations ({max_iterations}) reached, ending analysis")
        conclusion = _check_conclusion(analysis_result)
        return (conclusion if conclusion else "unknown"), analysis_result


class TraceAnalysisAgent:
    """Analyze the call trace, correcting and validating trace info obtained from external tools.
    analyze_trace already runs the internal tool-call loop, so we can return its result directly."""
    def __init__(self, analysis_model, tool_model, res_file):
        self.analysis_model = analysis_model
        self.tool_model = tool_model
        self.res_file = res_file

    def process(self, trace, sink):
        history_messages = [{"role": "user", "content": f"trace: {trace}, sink: {sink}"}]
        # analyze_trace already has a full tool-call loop (up to 5 rounds); return its final result
        analysis_result = self.analysis_model(history_messages, self.res_file)
        return analysis_result

def find_cmdi_results_files(root_dir):
    cmdi_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            '''switch to cmdi_results.json'''
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
                binary_path = data.get("path", "")  # Binary file path
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
    print("Binaries and vulnerabilities found:")
    for binary, data in results.items():
        if data["vulnerabilities"]:
            print(f"- {binary}: {len(data['vulnerabilities'])} high-risk vulnerabilities")

    for binary, data in results.items():
        if data["vulnerabilities"]:
            print(f"\n{'='*60}")
            print(f"Starting analysis of binary: {binary}")
            print(f"File path: {data['path']}")
            print(f"Vulnerability count: {len(data['vulnerabilities'])}")
            print(f"{'='*60}")

            # Automatically load the corresponding binary
            print(f"\n[AUTO-LOAD] Loading binary: {binary}")
            load_success = load_binary_for_analysis(binary, data["path"])

            if not load_success:
                print(f"[ERROR] Failed to load binary {binary}; skipping its analysis")
                continue

            # Show the currently loaded file info
            current_info = get_current_binary_info()
            print(f"[OK] Currently loaded file: {current_info['name']}")
            print(f"[PATH] {current_info['path']}")

            # Prompt user to confirm whether to continue
            res = input(f"\nContinue analyzing {binary}? (press Enter to continue, 'skip' to skip): ")
            if res.lower() == 'skip':
                continue

            # Analyze each vulnerability
            for i, item in enumerate(data["vulnerabilities"]):
                print(f"\n--- Analyzing vulnerability {i+1}/{len(data['vulnerabilities'])} ---")
                trace = item["trace"]
                sink = item["sink"]

                # Show vulnerability info
                print(f"Sink address: {sink.get('ins_addr', 'N/A')}")
                print(f"Sink function: {sink.get('function', 'N/A')}")
                if trace:
                    print(f"Trace start address: {trace[0].get('ins_addr', 'N/A')}")
                    print(f"Trace start function: {trace[0].get('function', 'N/A')}")

                # Filter specific addresses (preserve existing logic)
                if "0xb54c" in sink["ins_addr"] or "0xb574" in sink["ins_addr"] or "0xb96c" in sink["ins_addr"] or "0xaf08" in sink["ins_addr"] or "0xb5a0" in sink["ins_addr"] or "0x17b08" in sink["ins_addr"] or "0x1ae64" in sink["ins_addr"] or "0xc2a8" in sink["ins_addr"] or "0x102a8" in sink["ins_addr"] or "0x17ea0" in sink["ins_addr"]:
                    print("Skipping vulnerability at a filtered address")
                    continue

                # Append to the log file
                with open(res_file, "+a", encoding='utf-8') as f:
                    f.write(f"trace:{trace}, sink:{sink}\n")

                # Run the trace analysis
                print("Starting trace analysis...")
                trace_agent = TraceAnalysisAgent(analysis_model=analyze_trace, tool_model=tools_call, res_file=res_file)
                source = extract_source(trace_agent.process(trace, sink))
                print("Extracted Source:", source)

                # Run the controllability analysis
                print("Starting controllability analysis...")
                agent = AnalysisAgent(analysis_model=analyze_vulnerability, tool_model=tools_call, res_file=res_file)
                if_controllable, _llm_response = agent.process(trace, source)
                print("Final Response:", if_controllable)

            print(f"\nAll vulnerabilities of {binary} analyzed")

    print("\nAll binaries analyzed!")