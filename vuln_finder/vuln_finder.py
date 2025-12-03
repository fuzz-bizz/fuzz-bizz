import os
import re
from typing import List, Dict, Tuple, Any
import ast

VULNERABLE_SINKS = [
    'strcpy', 'strcat', 'sprintf', 'system', 'execve', 'memcpy', 'gets', 'scanf', 'read',
    'vprintf', 'vsprintf', 'sscanf', 'mmap', 'sendto', 'malloc', 'calloc', 'realloc', 'free', 'alloca', 'bcopy', 'bzero', 'memset', 'memmove', 'vsnprintf', 'snprintf', 
    'os.system', 'os.popen', 'subprocess.call', 'subprocess.check_output', 'eval', 'exec', 
    'pickle.load', 'pickle.loads', 'jinja2.render', 'yaml.load', 'input', 'socket.send', 'webbrowser.open',
    '.execute(', '.query(', 'template.render', 'db.raw_sql',
    'shell_exec', 'passthru', 'unserialize', 'document.write', 'innerHTML'
]

RISK_SCORES: Dict[str, int] = {
    'system': 10, 'execve': 10, 'eval': 10, 'pickle.loads': 10, 'unserialize': 10, 'gets': 10,
    'mmap': 10, 'yaml.load': 10, 'document.write': 10, 'free': 10, 'realloc': 10,
    'os.system': 9, 'os.popen': 9, 'exec': 9, 'shell_exec': 9, 'passthru': 9, 'scanf': 9, 'pickle.load': 9,
    'input': 9, 'innerHTML': 9, 'malloc': 9, 'calloc': 9,
    'strcpy': 8, 'strcat': 8, 'sprintf': 8, 'memcpy': 8, 'vprintf': 8, 'vsprintf': 8,
    'alloca': 8, 'bcopy': 8, 'bzero': 8, 'memset': 8, 'memmove': 8,
    '.execute(': 7, '.query(': 7, 'db.raw_sql': 7, 'jinja2.render': 7, 'vsnprintf': 7, 'snprintf': 7,
    'subprocess.call': 6, 'subprocess.check_output': 6, 'read': 6, 'template.render': 6,
    'sscanf': 6, 'sendto': 6, 'socket.send': 6, 'webbrowser.open': 6
}

FUNCTION_DEFINITION_PATTERNS = {
    '.py': [re.compile(r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*')],
    '.c': [re.compile(r'^\s*(?:static|public|private|protected)?\s*\w+[\s*]+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)'),],
    '.cpp': [re.compile(r'^\s*(?:static|public|private|protected)?\s*\w+[\s*]+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)'),],
    '.java': [re.compile(r'^\s*(?:static|public|private|protected)?\s*\w+[\s*]+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)'),],
    '.js': [
        re.compile(r'^\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)'),
        re.compile(r'^\s*(?:const|let|var)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function'),
    ]
}

def build_function_call_graph_py(filepath: str) -> Dict[str, List[Tuple[str, int]]]:
    """
    Parses a Python file using AST to build a Function Call Graph (FCG).
    
    Returns:
        A dict mapping caller_name -> list of (callee_name, call_line_number)
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read())

    fcg = {}
    current_func = 'Global_Scope'

    class CallGraphVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            nonlocal current_func
            parent_func = current_func
            current_func = node.name
            
            if current_func not in fcg:
                fcg[current_func] = []
            
            self.generic_visit(node)
            current_func = parent_func

        def visit_Call(self, node):
            callee_name = 'Unknown_Call'
            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    callee_name = f"{node.func.value.id}.{node.func.attr}"
                else:
                    callee_name = node.func.attr 
            
            if current_func not in fcg:
                 fcg[current_func] = []

            fcg[current_func].append((callee_name, node.lineno))

            self.generic_visit(node)
    
    visitor = CallGraphVisitor()
    visitor.visit(tree)
    
    return fcg

def find_parent_function(filepath: str, sink_line_num: int, extension: str) -> str:
    """
    Heuristically finds the name of the function containing the sink by searching
    backward from the sink line for a function definition pattern, using language-specific patterns.
    """
    patterns_to_use = FUNCTION_DEFINITION_PATTERNS.get(extension.lower(), [])
    if not patterns_to_use:
         patterns_to_use = FUNCTION_DEFINITION_PATTERNS.get('.c', [])

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            for i in range(sink_line_num - 1, -1, -1):
                line = lines[i]
                for pattern in patterns_to_use:
                    match = pattern.search(line)
                    if match:
                        return match.group(1)
            
            return "Global_Scope"
            
    except IOError:
        return "Unknown_File"


def find_function_definition_line(filepath: str, function_name: str, extension: str, max_search_line: int = None) -> int:
    """
    Finds the line number where a function is defined by searching backward from a reference line.
    Returns -1 if not found.
    """
    patterns_to_use = FUNCTION_DEFINITION_PATTERNS.get(extension.lower(), [])
    if not patterns_to_use:
         patterns_to_use = FUNCTION_DEFINITION_PATTERNS.get('.c', [])

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            search_end = max_search_line if max_search_line else len(lines)
            for i in range(search_end - 1, -1, -1):
                line = lines[i]
                for pattern in patterns_to_use:
                    match = pattern.search(line)
                    if match and match.group(1) == function_name:
                        return i + 1
            
            return -1
            
    except IOError:
        return -1


def extract_function_snippet(filepath: str, function_name: str, function_start_line: int, extension: str, context_lines: int = 3) -> str:
    """
    Extracts a code snippet containing the function. For C/C++/Java, tries to extract the full function.
    For Python, extracts the function with proper indentation handling.
    Returns the formatted snippet.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if function_start_line < 1 or function_start_line > len(lines):
            return ""
        
        func_start_idx = function_start_line - 1
        func_end_idx = func_start_idx
        
        if extension in ['.c', '.cpp', '.java', '.js']:
            brace_count = 0
            in_function = False
            
            for i in range(func_start_idx, len(lines)):
                line = lines[i]
                for char in line:
                    if char == '{':
                        brace_count += 1
                        in_function = True
                    elif char == '}':
                        brace_count -= 1
                        if in_function and brace_count == 0:
                            func_end_idx = i
                            break
                if in_function and brace_count == 0:
                    break
            
            if func_end_idx == func_start_idx:
                patterns = FUNCTION_DEFINITION_PATTERNS.get(extension.lower(), [])
                for i in range(func_start_idx + 1, min(func_start_idx + 50, len(lines))):
                    for pattern in patterns:
                        if pattern.search(lines[i]):
                            func_end_idx = i - 1
                            break
                    if func_end_idx > func_start_idx:
                        break
                if func_end_idx == func_start_idx:
                    func_end_idx = min(func_start_idx + 30, len(lines) - 1)
        
        elif extension == '.py':
            if func_start_idx >= len(lines):
                return ""
            
            base_indent = len(lines[func_start_idx]) - len(lines[func_start_idx].lstrip())
            
            func_end_idx = func_start_idx
            for i in range(func_start_idx + 1, len(lines)):
                line = lines[i]
                if not line.strip():
                    continue
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= base_indent and line.strip():
                    func_end_idx = i - 1
                    break
                func_end_idx = i
        
        else:
            func_end_idx = min(func_start_idx + 30, len(lines) - 1)
        
        snippet_lines = lines[func_start_idx:func_end_idx + 1]
        snippet_code = ''.join(snippet_lines).rstrip()
        
        normalized_path = filepath
        if filepath.startswith('/'):
            normalized_path = filepath
        
        formatted_snippet = f"[{normalized_path}:{function_start_line}] {snippet_code}"
        return formatted_snippet
        
    except Exception as e:
        print(f"Error extracting snippet from {filepath}: {e}")
        return ""


def analyze_file(filepath: str, sinks: List[str], scores: Dict[str, int]) -> List[Tuple[int, str, str, str, int]]:
    """
    Scans a single file for known vulnerable sink functions using the regex method.
    """
    findings = []
    file_extension = os.path.splitext(filepath)[1].lower()
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for sink in sinks:
                    pattern = r'\b' + re.escape(sink) + r' *\(|\b' + re.escape(sink) + r'='
                    
                    if re.search(pattern, line):
                        risk = scores.get(sink, 5)
                        parent_func = find_parent_function(filepath, line_num, file_extension)
                        findings.append((line_num, sink, parent_func, filepath, risk))
                        break
    except IOError as e:
        print(f"Error reading file {filepath}: {e}")

    return findings

def scan_codebase(root_dir: str, file_extensions: List[str]) -> List[Dict]:
    """
    Traverses a directory, builds the FCG, runs sink finding, and performs backward taint propagation.
    """
    sinks = VULNERABLE_SINKS
    scores = RISK_SCORES

    fcg_by_file = {}
    direct_findings = []
    
    print(f"Starting analysis (Phase 1: Build FCG and Find Direct Sinks) in directory: {root_dir}...")
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in ['.git', '__pycache__', 'venv', 'node_modules']]
        
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in file_extensions:
                filepath = os.path.join(dirpath, filename)
                
                if ext == '.py':
                    try:
                        fcg_by_file[filepath] = build_function_call_graph_py(filepath)
                    except Exception as e:
                        print(f"Warning: Could not build AST/FCG for {filepath}. Error: {e}")
                
                file_findings = analyze_file(filepath, sinks, scores) 
                direct_findings.extend(file_findings)

    propagated_findings: Dict[Tuple[str, str], Dict[str, Any]] = {} 

    for line, sink_name, parent_name, path, score in direct_findings:
        key = (path, parent_name)
        if key not in propagated_findings or score > propagated_findings[key].get('risk_score', 0):
             propagated_findings[key] = {
                'risk_score': score, 
                'sink_type': f"Direct Sink: {sink_name}",
                'line_number': line
             }
    
    MAX_DEPTH = 5
    MULTIPLIER = 0.9

    reverse_fcg: Dict[str, List[Tuple[str, str, int]]] = {}
    for filepath, fcg in fcg_by_file.items():
        for caller, callee_tuples in fcg.items():
            for callee_name, call_line in callee_tuples:
                if callee_name not in reverse_fcg:
                    reverse_fcg[callee_name] = []
                reverse_fcg[callee_name].append((filepath, caller, call_line))

    for depth in range(MAX_DEPTH):
        changed = False
        newly_propagated: Dict[Tuple[str, str], Dict[str, Any]] = {} 
        current_high_risk_functions = list(propagated_findings.items())
        
        for (callee_path, callee_name), callee_data in current_high_risk_functions:
            callee_risk = callee_data['risk_score']
            propagated_score = callee_risk * MULTIPLIER
            if propagated_score < 1:
                continue

            callers_of_callee = reverse_fcg.get(callee_name, [])

            for caller_path, caller_name, call_line in callers_of_callee:
                caller_key = (caller_path, caller_name)
                current_caller_risk = propagated_findings.get(caller_key, {}).get('risk_score', 0)

                if propagated_score > current_caller_risk:
                    newly_propagated[caller_key] = {
                        'risk_score': propagated_score,
                        'sink_type': f"Propagated from: {callee_name} (Depth {depth + 1})",
                        'line_number': call_line
                    }
                    changed = True
        
        for key, new_data in newly_propagated.items():
            if new_data['risk_score'] > propagated_findings.get(key, {}).get('risk_score', 0):
                propagated_findings[key] = new_data
        
        if not changed:
            break

    final_output = []
    
    for (filepath, parent_func), data in propagated_findings.items():
        if parent_func != 'Global_Scope' and data['risk_score'] >= 5:
            final_output.append({
                "risk_score": round(data['risk_score']),
                "sink_function": data['sink_type'],
                "parent_function": parent_func,
                "file_path": filepath,
                "line_number": data['line_number']
            })

    sorted_final_output = sorted(final_output, key=lambda x: x['risk_score'], reverse=True)


    print(f"Analysis complete. Found {len(sorted_final_output)} potential vulnerability entry points (Direct and Propagated).")
    return sorted_final_output


def generate_vulnerable_snippets(scan_results: List[Dict]) -> List[str]:
    """
    Converts scan results into formatted vulnerable snippets as expected by patcher.run().
    
    Args:
        scan_results: List of dictionaries from scan_codebase() containing vulnerability findings
    
    Returns:
        List of formatted snippet strings in the format: "[filepath:line] code..."
    """
    snippets = []
    
    for result in scan_results:
        filepath = result['file_path']
        parent_func = result['parent_function']
        line_number = result['line_number']
        extension = os.path.splitext(filepath)[1].lower()
        
        func_start_line = find_function_definition_line(filepath, parent_func, extension, line_number)
        
        if func_start_line > 0:
            snippet = extract_function_snippet(filepath, parent_func, func_start_line, extension)
            if snippet:
                snippets.append(snippet)
        else:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                if line_number > 0 and line_number <= len(lines):
                    start_idx = max(0, line_number - 5)
                    end_idx = min(len(lines), line_number + 5)
                    snippet_lines = lines[start_idx:end_idx]
                    snippet_code = ''.join(snippet_lines).rstrip()
                    
                    normalized_path = filepath
                    formatted_snippet = f"[{normalized_path}:{line_number}] {snippet_code}"
                    snippets.append(formatted_snippet)
            except Exception as e:
                print(f"Error generating fallback snippet from {filepath}: {e}")
    
    return snippets


if __name__ == "__main__":
    PROJECT_ROOT_DIR = '.'
    TARGET_EXTENSIONS = ['.py', '.c', '.cpp', '.java', '.js']

    results = scan_codebase(PROJECT_ROOT_DIR, TARGET_EXTENSIONS)
    
    print("\n--- Sorted Vulnerability Entry Points (Highest Risk First) ---")
    for result in results:
        print(
            f"[Score: {result['risk_score']:<2}] "
            f"File: {result['file_path']:<20} "
            f"Line: {result['line_number']:<4} "
            f"Parent: {result['parent_function']:<15} "
            f"Sink: {result['sink_function']}"
        )

    
    vulnerable_snippets = generate_vulnerable_snippets(results)
    for snippet in vulnerable_snippets:
        print(f"Snippet:\n{snippet}\n")