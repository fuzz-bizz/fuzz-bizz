# qe.py
#
# This non LLM Agent performs quality checks on proposed patches. It needs to perform three steps:
# 1. Apply the patch diff to the project.
# 2. Verify that the project is still compilable.
# 3. If it compiles, test it on the fuzzed vulnerable inputs.
# If anything it fails, it should revert the diff.

from shared.stringasxml import extract

import glob
import difflib
import logging
import os
import patch
import subprocess
import tempfile

class QualityEngineerAgent():
    def __init__(self):
        self.name = "quality engineer agent"
        self.patch_stack = []

    def make_diff(self, old_code, new_code, file_path):
        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=file_path,
            tofile=file_path,
        )
        return "".join(diff)

    def apply_patch(self, patches):
        for p in reversed(patches):
            file_path = extract(p, "file_path")
            old_code = extract(p, "old_code")
            new_code = extract(p, "new_code")
            diff = self.make_diff(old_code, new_code, file_path)
            logging.info(f"{self.name} is applying diff\n\n{diff}\n")
            ps = patch.fromstring(diff)
            if not ps.apply():
                return False
            self.patch_stack.append((old_code, new_code, file_path))

        return True

    def revert_patch(self):
        logging.info(f"{self.name} is reverting patch")
        while self.patch_stack:
            old_code, new_code, file_path = self.patch_stack.pop()
            diff = self.make_diff(new_code, old_code, file_path)
            ps = patch.fromstring(diff)
            if not ps.apply():
                raise RuntimeError("patch reversion failed")

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
                # On Windows, GCC created output_path + '.exe'
                if os.name == "nt" and not os.path.exists(output_path):
                    exe_path = output_path + ".exe"
                    if os.path.exists(exe_path):
                        os.rename(exe_path, output_path)
                        logging.info(f"Renamed {exe_path} -> {output_path}")
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
