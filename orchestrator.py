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
    patcher.run()

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
