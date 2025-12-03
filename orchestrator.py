# orchestrator.py
#
# Main entry point for fuzz-bizz CRS (Cyber Reasoning System).
# Orchestrates the full pipeline: seed generation -> fuzzing -> patching

import patcher.patcher as patcher
import seed_gen.seed_gen as seed_gen
import fuzzer.fuzzer as fuzzer

import logging
import sys
import subprocess
import time
import vuln_finder.vuln_finder as vuln_finder

import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

# ----------------- Logging setup -----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ----------------- Configuration -----------------
@dataclass
class Config:
    """Configuration settings for the orchestrator."""
    project: str = "project"
    model: str = "deepseek-coder:6.7b-instruct-q4_K_M"
    timeout: int = 120
    seeds: int = 8
    output: Optional[str] = None


def load_config(config_path: str = "config.yaml") -> Config:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the config file (default: config.yaml)
        
    Returns:
        Config object with settings
    """
    path = Path(config_path)
    
    if not path.exists():
        # Return defaults if no config file
        return Config()
    
    with open(path, 'r') as f:
        data = yaml.safe_load(f) or {}
    
    return Config(
        project=data.get('project', 'project'),
        model=data.get('model', 'deepseek-coder:6.7b-instruct-q4_K_M'),
        timeout=data.get('timeout', 120),
        seeds=data.get('seeds', 8),
        output=data.get('output'),
    )


# ----------------- Source Code Utilities -----------------
def read_source_files(project_dir: str) -> str:
    """
    Read all C/C++ source files from project directory.
    
    Args:
        project_dir: Path to project directory
        
    Returns:
        Concatenated source code with file markers
    """
    source_parts = []
    project_path = Path(project_dir)
    
    extensions = ['*.c', '*.cpp', '*.cc', '*.h', '*.hpp']
    excluded_dirs = {'build', 'build_afl', 'fuzz_output', 'fuzz_corpus', '.git'}
    
    for ext in extensions:
        for file in project_path.glob(f'**/{ext}'):
            # Skip excluded directories
            if any(ex in file.parts for ex in excluded_dirs):
                continue
            
            try:
                content = file.read_text()
                rel_path = file.relative_to(project_path)
                source_parts.append(f"// ===== FILE: {rel_path} =====\n")
                source_parts.append(content)
                source_parts.append("\n\n")
            except Exception as e:
                logger.warning(f"Failed to read {file}: {e}")
    
    full_source = "".join(source_parts)
    logger.info(f"Read {len(source_parts)//3} source files ({len(full_source)} chars)")
    return full_source


# ----------------- Dependency Checks -----------------
def check_afl() -> bool:
    """Check if AFL++ is installed."""
    try:
        result = subprocess.run(
            ["afl-fuzz", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        logger.info("✓ AFL++ is installed")
        return True
    except FileNotFoundError:
        logger.error("✗ AFL++ is NOT installed")
        logger.info("  macOS: brew install aflplusplus")
        logger.info("  Linux: apt install afl++")
        return False
    except Exception as e:
        logger.error(f"✗ Error checking AFL++: {e}")
        return False


def check_compiler() -> bool:
    """Check if a C compiler is available."""
    compilers = ["afl-clang-fast", "afl-gcc", "clang", "gcc"]
    
    for compiler in compilers:
        try:
            result = subprocess.run(
                [compiler, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"✓ C compiler '{compiler}' is available")
                return True
        except:
            continue
    
    logger.error("✗ No C compiler found")
    logger.info("  macOS: xcode-select --install")
    logger.info("  Linux: apt install build-essential")
    return False


def check_ollama() -> bool:
    """Check if Ollama is installed."""
    try:
        result = subprocess.run(
            ["ollama", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        logger.info(f"✓ Ollama is installed: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        logger.error("✗ Ollama is NOT installed")
        logger.info("  Install from: https://ollama.com/download")
        return False
    except Exception as e:
        logger.error(f"✗ Error checking Ollama: {e}")
        return False


def check_all_dependencies() -> bool:
    """Check all required dependencies. Returns True if all are satisfied."""
    logger.info("Checking dependencies...")
    
    results = {
        'AFL++': check_afl(),
        'Compiler': check_compiler(),
        'Ollama': check_ollama(),
    }
    
    all_ok = all(results.values())
    
    if not all_ok:
        logger.error("\nMissing dependencies. Please install them and try again.")
        sys.exit(1)
    
    logger.info("All dependencies satisfied.\n")
    return all_ok


# ----------------- Main Pipeline -----------------
def run_full_pipeline(project_dir: str,
                      fuzz_timeout: int = 120,
                      num_seeds: int = 8,
                      heatmap: Optional[Dict[str, float]] = None) -> bool:
    """
    Run the complete CRS pipeline: seed-gen -> fuzz -> patch.
    
    Args:
        project_dir: Path to project source directory
        fuzz_timeout: Fuzzing timeout in seconds
        num_seeds: Number of seeds to generate
        heatmap: Optional function priority heatmap from static analysis
        
    Returns:
        True if vulnerabilities were found and patched
    """
    project_path = Path(project_dir)
    project_name = project_path.name
    
    # Scan the codebase for vulnerabilities
    target_extensions = ['.py', '.c', '.cpp', '.java', '.js']
    
    logger.info(f"Scanning codebase in {project_dir} for vulnerabilities...")
    scan_results = vuln_finder.scan_codebase(project_dir, target_extensions)
    
    # Generate vulnerable snippets from scan results
    vulnerable_snippets = vuln_finder.generate_vulnerable_snippets(scan_results)
    
    if not vulnerable_snippets:
        logger.warning("No vulnerabilities found in codebase. Using placeholder inputs.")
        vulnerable_snippets = ["""
[project/fastparse.c:4] void parse_input(const char *input) {
    char buffer[16];
    printf("Parsing input...\n");
    strcpy(buffer, input);
    printf("Received: %s\n", buffer);
}
"""]
    
    logger.info(f"Found {len(vulnerable_snippets)} vulnerable snippet(s)")
    # with open("vulnerable_snippets.txt", "w", encoding="utf-8") as f:
    #     for idx, snippet in enumerate(vulnerable_snippets, 1):
    #         f.write(f"\n--- Vulnerable Snippet #{idx} ---\n{snippet}\n")
    # logger.info(f"Wrote vulnerable snippets to vulnerable_snippets.txt")
    
    logger.info("=" * 60)
    logger.info(f"FUZZ-BIZZ CRS - Starting Pipeline")
    logger.info(f"Project: {project_name}")
    logger.info(f"Directory: {project_dir}")
    logger.info("=" * 60)
    
    # Step 1: Read source code
    logger.info("\n[STEP 1] Reading source code...")
    source_code = read_source_files(project_dir)
    
    if not source_code.strip():
        logger.error("No source code found in project directory")
        return False
    
    # Step 2: Generate seeds
    logger.info(f"\n[STEP 2] Generating {num_seeds} seeds...")
    seeds = seed_gen.run(
        project_name=project_name,
        source_code=source_code,
        heatmap=heatmap,
        num_seeds=num_seeds
    )
    
    logger.info(f"Generated {len(seeds)} seeds")
    for i, seed in enumerate(seeds[:5]):  # Log first 5
        preview = seed[:50].hex() if len(seed) > 50 else seed.hex()
        logger.debug(f"  Seed {i}: {preview}...")
    
    # Step 3: Run fuzzer
    logger.info(f"\n[STEP 3] Fuzzing for {fuzz_timeout} seconds...")
    fuzz_result = fuzzer.run(
        project_dir=project_dir,
        target_binary="target",
        initial_seeds=seeds,
        timeout_seconds=fuzz_timeout
    )
    
    logger.info(f"Fuzzing complete:")
    logger.info(f"  - Executions: {fuzz_result.total_execs}")
    logger.info(f"  - Coverage: {fuzz_result.coverage_pct}%")
    logger.info(f"  - Unique crashes: {fuzz_result.unique_crashes}")
    logger.info(f"  - Queue size: {fuzz_result.queue_size}")
    
    # Step 4: Patch if crashes found
    if fuzz_result.crashes:
        logger.info(f"\n[STEP 4] Patching {len(fuzz_result.crashes)} crashes...")
        
        # Use full source code as context for patcher
        snippets = [source_code] + [vulnerable_snippets]
        
        # Run patcher
        patcher.run(
            project_name=project_name,
            snippets=snippets,
            stacktraces=fuzz_result.stacktraces,
            fuzzed_inputs=fuzz_result.crashes
        )
        
        logger.info("\n" + "=" * 60)
        logger.info("Pipeline complete - patches generated!")
        logger.info("=" * 60)
        return True
    else:
        logger.info("\n[STEP 4] No crashes found - no patching needed")
        logger.info("\n" + "=" * 60)
        logger.info("Pipeline complete - no vulnerabilities found")
        logger.info("=" * 60)
        return False


# ----------------- Ensure Ollama is running -----------------
def ensure_ollama_running():
    """Ensure Ollama is running for LLM inference."""
    def is_running():
        try:
            subprocess.run(
                ["ollama", "list"], 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=5
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            logger.error("Ollama not found. Please install: https://ollama.com/download")
            sys.exit(1)

    if not is_running():
        logger.info("Starting Ollama...")
        subprocess.Popen(
            ["ollama", "serve"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        # Wait for Ollama to start
        for _ in range(10):
            if is_running():
                break
            time.sleep(1)
        else:
            logger.error("Failed to start Ollama")
            sys.exit(1)

    logger.info("Ollama is running")


def setup_logging(output_file: Optional[str] = None):
    """Set up logging configuration."""
    if output_file:
        file_handler = logging.FileHandler(output_file)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.INFO)
        
        # Also add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        logger.info(f"Logging to {output_file}")


# ----------------- Main -----------------
def main():
    # Load configuration from config.yaml
    config = load_config("config.yaml")
    
    # Set up logging
    setup_logging(config.output)
    
    # Check all dependencies first
    check_all_dependencies()
    
    # Update model in shared config
    import shared.config as shared_config
    shared_config.OLLAMA_MODEL = config.model
    logger.info(f"Using model: {config.model}")
    
    # Ensure Ollama is running
    ensure_ollama_running()
    
    # Run full pipeline
    run_full_pipeline(
        project_dir=config.project,
        fuzz_timeout=config.timeout,
        num_seeds=config.seeds
    )


# ----------------- Script entry point -----------------
if __name__ == "__main__":
    main()
