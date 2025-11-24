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

    def make_diff(self, old_code, new_code, file_path, identifier):
        # Extract line number from identifier
        match = re.search(r'line (\d+)', identifier)
        if not match:
            raise ValueError(f"Could not find line number in identifier: {identifier}")
        line_number = int(match.group(1))  # 1-based

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
            identifier = extract(p, "identifier")[0]
            diff, file_lines = self.make_diff(old_code, new_code, file_path, identifier)
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
