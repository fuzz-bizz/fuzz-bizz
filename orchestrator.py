# test.py

import patcher.patcher as patcher
from shared.config import OLLAMA_MODEL

import argparse
import logging
import sys
import subprocess
import time

# ----------------- Logging setup -----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ----------------- Main function -----------------
def main():

    # Example Inputs (will eventually be removed)
    project_name = "libfastparse"
    vulnerable_snippets = ["""
[project/fastparse.c:4] void parse_input(const char *input) {
    char buffer[16];
    printf("Parsing input...\n");
    strcpy(buffer, input);
    printf("Received: %s\n", buffer);
}
"""]
    stacktraces = ["""
#0  0x00007ffff7a334bb in __strcpy_ssse3 () from /usr/lib/libc.so.6
#1  0x0000555555555152 in parse_input (input=0x7fffffffe8d0 "AAAAAA...") at fastparse.c:4
#2  0x00005555555551d4 in main (argc=2, argv=0x7fffffffe7c8) at fastparse.c:25
"""]
    fuzzed_inputs = [b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]

    patcher.run(project_name, vulnerable_snippets, stacktraces, fuzzed_inputs)

# ----------------- Argument parsing -----------------
def parse_args():
    parser = argparse.ArgumentParser(description="Run crs with optional commands")
    parser.add_argument(
        "-m", "--model",
        type=str,
        help="Ollama model name to use (overrides shared.config.OLLAMA_MODEL)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Redirect all output (logging, stdout, stderr) to a file"
    )
    args = parser.parse_args()
    if args.model:
        logger.info(f"Overriding OLLAMA_MODEL to {args.model}")
        OLLAMA_MODEL = args.model
    if args.output:
        file_handler = logging.FileHandler(args.output)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.INFO)
        sys.stdout = open(args.output, "a")
        sys.stderr = open(args.output, "a")
        root_logger.info(f"Redirecting all output to {args.output}")

# ----------------- Ensure Ollama is running -----------------
def ensure_ollama_running():
    def is_running():
        try:
            subprocess.run(
                ["ollama", "list"], capture_output=True, text=True, check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            logger.error("Ollama executable not found. Please install Ollama: https://ollama.com/download")
            sys.exit()

    if not is_running():
        logger.info("Ollama is not running, starting it...")
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Wait until Ollama is ready
        for _ in range(10):
            if is_running():
                break
            time.sleep(1)
        else:
            logger.error("Failed to start Ollama.")
            sys.exit()

    logger.info("Ollama is running.")

# ----------------- Script entry point -----------------
if __name__ == "__main__":
    parse_args()
    ensure_ollama_running()
    main()
