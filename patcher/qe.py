# qe.py
#
# This non LLM Agent performs quality checks on proposed patches. It needs to perform three steps:
# 1. Apply the patch diff to the project.
# 2. Verify that the project is still compilable.
# 3. If it compiles, test it on the fuzzed vulnerable inputs.
# If anything it fails, it should revert the diff.

from shared.stringasxml import extract

import difflib
import glob
import logging
import os
from patch_ng import fromstring
import re
import subprocess
import tempfile

class QualityEngineerAgent():
    def __init__(self):
        self.name = "quality engineer agent"
        self.patch_stack = []

    def find_line_number(self, file_path, old_code):
        """
        Find the starting line number of old_code in file using fuzzy matching.
        Returns 1-based line number, or None if no good match found.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            file_lines = f.readlines()
        
        old_lines = old_code.strip().splitlines()
        if not old_lines:
            return None
        
        window_size = len(old_lines)
        best_score = 0.0
        best_start = None
        
        # Slide window over file
        for start in range(len(file_lines) - window_size + 1):
            window = [line.rstrip('\n\r') for line in file_lines[start:start + window_size]]
            
            # Calculate average line-by-line similarity
            total = 0.0
            for file_line, old_line in zip(window, old_lines):
                ratio = difflib.SequenceMatcher(None, file_line.strip(), old_line.strip()).ratio()
                total += ratio
            score = total / window_size
            
            if score > best_score:
                best_score = score
                best_start = start
        
        # Require at least 60% similarity
        if best_score < 0.6:
            logging.warning(f"No good match found for old_code (best score: {best_score:.2f})")
            return None
        
        logging.info(f"Found match at line {best_start + 1} with score {best_score:.2f}")
        return best_start + 1  # Convert to 1-based

    def make_diff(self, old_code, new_code, file_path, line_number):
        # line_number is now passed directly (1-based)
        if not line_number:
            return "", ""

        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)
        if (old_lines[0] == "\n"):
            old_lines = old_lines[1:]
        if (new_lines[0] == "\n"):
            new_lines = new_lines[1:]

        with open(file_path, 'r', encoding='utf-8') as f:
            file_lines = f.readlines()

        old_lines = file_lines[line_number - 1 : line_number - 1 + len(old_lines)]

        # Generate the diff and get it as a string
        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=file_path,
            tofile=file_path,
        )
        diff_str = "".join(diff)

        # Replace the @@ header to use the LLM-provided line number
        # Pattern: @@ -<start>,<count> +<start>,<count> @@
        def replace_header(match):
            old_count = len(old_lines)
            new_count = len(new_lines)
            return f"@@ -{line_number},{old_count} +{line_number},{new_count} @@"

        diff_str = re.sub(r'@@ -\d+,\d+ \+\d+,\d+ @@', replace_header, diff_str)

        return diff_str, file_lines

    def apply_patch(self, patches):
        for p in reversed(patches):
            file_path = extract(p, "file_path")[0]
            old_code = extract(p, "old_code")[0]
            new_code = extract(p, "new_code")[0]
            
            # Normalize file path - if not found, try with project/ prefix
            if not os.path.exists(file_path):
                # Try adding project/ prefix
                alt_path = os.path.join("project", os.path.basename(file_path))
                if os.path.exists(alt_path):
                    logging.info(f"File path normalized: {file_path} -> {alt_path}")
                    file_path = alt_path
                else:
                    logging.error(f"File not found: {file_path} (also tried {alt_path})")
                    return False
            
            # Find line number using fuzzy matching instead of relying on LLM
            line_number = self.find_line_number(file_path, old_code)
            
            diff, file_lines = self.make_diff(old_code, new_code, file_path, line_number)
            if diff == "":
                return False
            logging.info(f"{self.name} is applying diff\n\n{diff}\n")
            ps = fromstring(diff.encode("utf-8"))
            if not ps or not ps.apply():
                return False
            self.patch_stack.append((file_path, file_lines))

        return True

    def revert_patch(self):
        logging.info(f"{self.name} is reverting patch")
        while self.patch_stack:
            file_path, file_lines = self.patch_stack.pop()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(file_lines)

        # Clean up compiled executables
        for exe_path in ["project/executable", "project/executable.exe"]:
            if os.path.exists(exe_path):
                try:
                    os.remove(exe_path)
                    logging.info(f"Removed {exe_path}")
                except Exception as e:
                    logging.warning(f"Failed to remove {exe_path}: {e}")

    def compile(self):
        logging.info(f"{self.name} is compiling")
        output_path = "project/executable"  # desired final name without .exe

        # Construct compilation command
        source_files = glob.glob("project/*.c")
        cmd = ["gcc"] + source_files + ["-o", output_path]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            success = result.returncode == 0

            if success:
                logging.info("Compilation succeeded")
            else:
                logging.info("Compilation failed")

            return success, result.stdout, result.stderr

        except Exception as e:
            logging.info("Error running gcc")
            return False, "", str(e)

    def test_inputs(self, inputs):
        logging.info(f"{self.name} is testing fuzzed inputs")

        if os.path.exists("project/executable"):
            exe_path = "./project/executable"
        else:
            exe_path = "./project/executable.exe"

        for input_data in inputs:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as temp_input_file:
                    temp_input_file.write(input_data)
                    temp_input_file.close()

                    result = subprocess.run(
                        [
                            "gdb", "-q", "--batch",
                            "-ex", f"run < {temp_input_file.name}",
                            "--args", exe_path
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10
                    )

                    os.remove(temp_input_file.name)

                    # Non-zero return code = crash/failure
                    if result.returncode != 0:
                        logging.info(f"Program failed for input: {input_data}")

                        return {
                            "input": input_data,
                            "stack_trace": result.stderr,   # gdb stack trace
                            "stdout": result.stdout,
                            "stderr": result.stderr
                        }

            except subprocess.TimeoutExpired:
                logging.info(f"Program timed out for input: {input_data}")

                return {
                    "input": input_data,
                    "stack_trace": "Timeout expired during execution.",
                    "stdout": "",
                    "stderr": "Timeout expired during execution."
                }

            except Exception as e:
                logging.info(f"Error running program for input {input_data}: {e}")

                return {
                    "input": input_data,
                    "stack_trace": str(e),
                    "stdout": "",
                    "stderr": str(e)
                }

        # If we reach here, all inputs succeeded
        logging.info("all fuzzed inputs passed! we are done!")
        return None
