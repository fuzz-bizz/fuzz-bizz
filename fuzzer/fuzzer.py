# fuzzer.py
#
# Main fuzzer orchestration. Compiles the target with AFL++ instrumentation,
# runs fuzzing campaigns, and collects crashes.

from fuzzer.afl_wrapper import AFLRunner, AFLConfig, check_afl_available
from fuzzer.compiler import InstrumentedCompiler
from fuzzer.corpus import CorpusManager
from fuzzer.crash_processor import CrashProcessor

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Result of a fuzzing campaign."""
    crashes: List[bytes]          # Crash input data
    stacktraces: List[str]        # Corresponding stack traces
    coverage_pct: float           # Estimated coverage percentage
    total_execs: int              # Total executions
    unique_crashes: int           # Deduplicated crash count
    exec_speed: str               # Executions per second
    queue_size: int               # Number of interesting inputs found


@dataclass 
class FuzzConfig:
    """Configuration for a fuzzing run."""
    timeout_seconds: int = 300    # Total fuzzing time
    sanitizers: List[str] = None  # Sanitizers to use
    memory_limit: str = "none"    # Memory limit for target
    
    def __post_init__(self):
        if self.sanitizers is None:
            self.sanitizers = ["address", "undefined"]


def run(project_dir: str,
        target_binary: str = "target",
        initial_seeds: List[bytes] = None,
        timeout_seconds: int = 300,
        config: FuzzConfig = None) -> FuzzResult:
    """
    Main fuzzing entry point.
    
    This function:
    1. Compiles the project with AFL++ instrumentation
    2. Sets up the corpus with initial seeds
    3. Runs AFL++ fuzzing
    4. Processes and deduplicates crashes
    
    Args:
        project_dir: Path to project source code directory
        target_binary: Name of the main executable to fuzz
        initial_seeds: List of initial seed inputs (bytes)
        timeout_seconds: How long to fuzz
        config: Additional fuzzing configuration
        
    Returns:
        FuzzResult with crashes and metadata
    """
    config = config or FuzzConfig(timeout_seconds=timeout_seconds)
    project_path = Path(project_dir)
    
    logger.info(f"=== Fuzzer Starting for {project_dir} ===")
    logger.info(f"Timeout: {timeout_seconds}s")
    
    # Check AFL++ is available
    if not check_afl_available():
        logger.error("AFL++ not found! Please install AFL++:")
        logger.error("  macOS: brew install aflplusplus")
        logger.error("  Linux: apt install afl++")
        return FuzzResult([], [], 0.0, 0, 0, "0", 0)
    
    # Step 1: Compile with instrumentation
    logger.info("Step 1: Compiling with AFL++ instrumentation")
    compiler = InstrumentedCompiler(project_path)
    instrumented_binary = compiler.compile_with_afl(
        target_name=target_binary,
        sanitizers=config.sanitizers
    )
    
    if not instrumented_binary:
        logger.error("Failed to compile with AFL++ instrumentation")
        return FuzzResult([], [], 0.0, 0, 0, "0", 0)
    
    logger.info(f"Compiled: {instrumented_binary}")
    
    # Step 2: Set up corpus
    logger.info("Step 2: Setting up corpus")
    corpus_path = project_path / "fuzz_corpus"
    corpus = CorpusManager(corpus_path)
    
    # Clear any old corpus
    corpus.clear()
    
    # Add initial seeds
    if initial_seeds:
        logger.info(f"Adding {len(initial_seeds)} initial seeds")
        corpus.add_seeds(initial_seeds)
    
    # Ensure at least one seed exists
    if corpus.count() == 0:
        logger.info("No seeds provided, adding default seed")
        corpus.add_seed(b"AAAA", "default")
    
    logger.info(f"Corpus ready: {corpus.count()} seeds, {corpus.total_size()} bytes")
    
    # Step 3: Run AFL++
    logger.info("Step 3: Running AFL++")
    output_dir = project_path / "fuzz_output"
    
    # Clean old output
    if output_dir.exists():
        shutil.rmtree(output_dir)
    
    afl_config = AFLConfig(
        memory_limit=config.memory_limit,
        use_asan="address" in (config.sanitizers or [])
    )
    
    runner = AFLRunner(
        target_binary=instrumented_binary,
        corpus_dir=corpus.input_dir,
        output_dir=output_dir,
        timeout=timeout_seconds,
        config=afl_config
    )
    
    afl_result = runner.run()
    
    logger.info(f"AFL++ finished: {afl_result.get('total_execs', 0)} executions")
    logger.info(f"Found {afl_result.get('unique_crashes', 0)} crashes")
    
    # Step 4: Process crashes
    logger.info("Step 4: Processing crashes")
    crashes_dir = output_dir / "default" / "crashes"
    processor = CrashProcessor(crashes_dir)
    
    # Use a standard compiled binary for crash reproduction
    # (ASAN binary without AFL instrumentation gives cleaner traces)
    repro_binary = compiler.compile_standard(
        target_name=f"{target_binary}_repro",
        sanitizers=config.sanitizers
    )
    
    if repro_binary:
        crash_inputs, stacktraces = processor.process_crashes(repro_binary)
    else:
        # Fall back to instrumented binary
        crash_inputs, stacktraces = processor.process_crashes(instrumented_binary)
    
    result = FuzzResult(
        crashes=crash_inputs,
        stacktraces=stacktraces,
        coverage_pct=afl_result.get("coverage", 0.0),
        total_execs=afl_result.get("total_execs", 0),
        unique_crashes=len(crash_inputs),
        exec_speed=str(afl_result.get("exec_speed", "0")),
        queue_size=afl_result.get("queue_size", 0)
    )
    
    logger.info(f"=== Fuzzing Complete ===")
    logger.info(f"Unique crashes: {result.unique_crashes}")
    logger.info(f"Coverage: {result.coverage_pct}%")
    logger.info(f"Total executions: {result.total_execs}")
    
    return result


def run_on_compiled_binary(binary_path: str,
                           corpus_dir: str,
                           output_dir: str,
                           timeout_seconds: int = 300) -> FuzzResult:
    """
    Run fuzzing on an already-compiled binary.
    
    Use this when you've manually compiled the target or have
    a pre-built instrumented binary.
    
    Args:
        binary_path: Path to instrumented binary
        corpus_dir: Directory with input seeds
        output_dir: Directory for AFL++ output
        timeout_seconds: Fuzzing timeout
        
    Returns:
        FuzzResult with crashes and metadata
    """
    binary_path = Path(binary_path)
    corpus_path = Path(corpus_dir)
    output_path = Path(output_dir)
    
    if not binary_path.exists():
        logger.error(f"Binary not found: {binary_path}")
        return FuzzResult([], [], 0.0, 0, 0, "0", 0)
    
    if not corpus_path.exists() or not list(corpus_path.iterdir()):
        logger.error(f"Corpus empty or missing: {corpus_path}")
        return FuzzResult([], [], 0.0, 0, 0, "0", 0)
    
    # Clean old output
    if output_path.exists():
        shutil.rmtree(output_path)
    
    runner = AFLRunner(
        target_binary=binary_path,
        corpus_dir=corpus_path,
        output_dir=output_path,
        timeout=timeout_seconds
    )
    
    afl_result = runner.run()
    
    # Process crashes
    crashes_dir = output_path / "default" / "crashes"
    processor = CrashProcessor(crashes_dir)
    crash_inputs, stacktraces = processor.process_crashes(binary_path)
    
    return FuzzResult(
        crashes=crash_inputs,
        stacktraces=stacktraces,
        coverage_pct=afl_result.get("coverage", 0.0),
        total_execs=afl_result.get("total_execs", 0),
        unique_crashes=len(crash_inputs),
        exec_speed=str(afl_result.get("exec_speed", "0")),
        queue_size=afl_result.get("queue_size", 0)
    )
