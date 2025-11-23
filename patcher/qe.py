# qe.py
#
# This non LLM Agent performs quality checks on proposed patches. It needs to perform three steps:
# 1. Apply the patch diff to the project.
# 2. Verify that the project is still compilable.
# 3. If it compiles, test it on the fuzzed vulnerable inputs.
# If anything it fails, it should revert the diff.

from shared.stringasxml import extract

import difflib
import logging
import os
import patch
import signal
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

    def compile(self):
        output_path = "project/executable"

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

            # Compilation succeeded (exit code 0)
            return result.returncode == 0

        except Exception:
            # Something went wrong running GCC
            return False

    def test_inputs(self, inputs):
        failed_inputs = []  # List to store inputs that caused a failure
        stack_traces = []  # List to store corresponding stack traces for failed inputs

        # Iterate over all the inputs to test
        for input_data in inputs:
            try:
                # Create a temporary file for the input data
                with tempfile.NamedTemporaryFile(delete=False) as temp_input_file:
                    # Write the input data to the temporary file
                    temp_input_file.write(input_data)
                    temp_input_file.close()  # Close the file so gdb can open it

                    # Run the program using gdb to capture stack traces
                    result = subprocess.run(
                        ["gdb", "-q", "--batch", "-ex", f"run < {temp_input_file.name}", "--args", "./project/executable"],
                        stdout=subprocess.PIPE,  # Capture standard output
                        stderr=subprocess.PIPE,  # Capture standard error (this will include stack trace on crash)
                        text=True,  # Interpret output as text
                        timeout=10  # Optional: Set a timeout to avoid infinite hangs (in seconds)
                    )

                    # Check if the process crashed (non-zero return code)
                    if result.returncode != 0:
                        logging.info(f"Program failed for input: {input_data}")
                        failed_inputs.append(input_data)

                        # Capture the stack trace from stderr (stderr should include the gdb stack trace)
                        stack_traces.append(result.stderr)

                    # Clean up the temporary file
                    os.remove(temp_input_file.name)

            except subprocess.TimeoutExpired:
                # Handle case where the program hangs and exceeds the timeout
                logging.info(f"Program timed out for input: {input_data}")
                failed_inputs.append(input_data)
                stack_traces.append("Timeout expired during execution.")  # Record a timeout error message
            except Exception as e:
                # If there's an exception running the subprocess, log it
                logging.info(f"Error running program for input {input_data}: {e}")
                failed_inputs.append(input_data)
                stack_traces.append(str(e))  # Capture the exception message

        # If all inputs passed successfully, return None
        if not failed_inputs:
            return None

        # Return a list of dictionaries, each containing the input and corresponding stack trace
        return [{"input": input_data, "stack_trace": trace} for input_data, trace in zip(failed_inputs, stack_traces)]
