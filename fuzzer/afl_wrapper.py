# afl_wrapper.py
#
# Wraps AFL++ as a subprocess, handling configuration, execution, and output parsing.

import logging
import os
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


@dataclass
class AFLConfig:
    """AFL++ configuration options."""
    memory_limit: str = "none"       # Memory limit (e.g., "500M", "none")
    use_asan: bool = True            # Enable AddressSanitizer support
    dictionary: Optional[Path] = None  # Optional dictionary file
    extra_args: List[str] = field(default_factory=list)  # Additional AFL arguments
    skip_cpufreq: bool = True        # Skip CPU frequency check (for VMs/containers)
    no_ui: bool = True               # Disable UI for scripting
    use_stdin: bool = True           # Feed input via stdin (False = use @@ file argument)


class AFLRunner:
    """
    Runs AFL++ fuzzing campaigns.
    
    Handles:
    - Command line construction
    - Environment setup
    - Execution and timeout
    - Statistics parsing
    """
    
    def __init__(self,
                 target_binary: Path,
                 corpus_dir: Path,
                 output_dir: Path,
                 timeout: int = 300,
                 config: AFLConfig = None):
        """
        Initialize AFL++ runner.
        
        Args:
            target_binary: Path to instrumented target binary
            corpus_dir: Directory with input seeds
            output_dir: Directory for AFL++ output
            timeout: Fuzzing timeout in seconds
            config: AFL configuration options
        """
        self.target_binary = Path(target_binary)
        self.corpus_dir = Path(corpus_dir)
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.config = config or AFLConfig()
        
        # AFL output subdirectories
        self.crashes_dir = self.output_dir / "default" / "crashes"
        self.queue_dir = self.output_dir / "default" / "queue"
        self.stats_file = self.output_dir / "default" / "fuzzer_stats"
    
    def _build_command(self) -> List[str]:
        """Build the AFL++ command line."""
        cmd = ["afl-fuzz"]
        
        # Input/output directories
        cmd.extend(["-i", str(self.corpus_dir)])
        cmd.extend(["-o", str(self.output_dir)])
        
        # Memory limit
        cmd.extend(["-m", self.config.memory_limit])
        
        # Time limit (-V for total time)
        cmd.extend(["-V", str(self.timeout)])
        
        # Dictionary
        if self.config.dictionary and self.config.dictionary.exists():
            cmd.extend(["-x", str(self.config.dictionary)])
        
        # Extra args
        cmd.extend(self.config.extra_args)
        
        # Target binary
        cmd.append("--")
        cmd.append(str(self.target_binary))
        
        # Use @@ for file input, or omit for stdin input
        if not self.config.use_stdin:
            cmd.append("@@")
        
        return cmd
    
    def _setup_environment(self) -> Dict[str, str]:
        """Set up environment variables for AFL++."""
        env = os.environ.copy()
        
        if self.config.skip_cpufreq:
            env["AFL_SKIP_CPUFREQ"] = "1"
        
        if self.config.no_ui:
            env["AFL_NO_UI"] = "1"
        
        if self.config.use_asan:
            env["AFL_USE_ASAN"] = "1"
            # ASAN options - AFL++ requires symbolize=0 during fuzzing
            env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=0:detect_leaks=0"
        
        # Disable AFL affinity (for VMs/containers)
        env["AFL_NO_AFFINITY"] = "1"
        
        # Skip binary check (if instrumentation is confirmed)
        env["AFL_SKIP_BIN_CHECK"] = "1"
        
        # Skip macOS crash reporter check (critical for macOS)
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        
        return env
    
    def run(self) -> Dict[str, Any]:
        """
        Run AFL++ fuzzing campaign.
        
        Returns:
            Dictionary with fuzzing statistics and results
        """
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Build command
        cmd = self._build_command()
        env = self._setup_environment()
        
        logger.info(f"Starting AFL++: {' '.join(cmd)}")
        logger.info(f"Timeout: {self.timeout} seconds")
        
        try:
            # Run AFL++ with slightly more time than requested for cleanup
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60
            )
            
            # Log output for debugging
            if result.stdout:
                logger.debug(f"AFL++ stdout: {result.stdout[:500]}")
            if result.stderr:
                # Check for errors - AFL++ outputs to stderr
                if "PROGRAM ABORT" in result.stderr or "[-]" in result.stderr:
                    logger.error(f"AFL++ error: {result.stderr[:1000]}")
                else:
                    logger.debug(f"AFL++ stderr: {result.stderr[:500]}")
            
            # Check return code
            if result.returncode != 0:
                logger.warning(f"AFL++ exited with code {result.returncode}")
                # Always log stderr on failure
                logger.error(f"AFL++ stderr: {result.stderr if result.stderr else '(empty)'}")
                logger.error(f"AFL++ stdout: {result.stdout if result.stdout else '(empty)'}")
            
        except subprocess.TimeoutExpired:
            logger.info("AFL++ timeout reached (expected behavior)")
        except Exception as e:
            logger.error(f"AFL++ execution error: {e}")
            return {"error": str(e), "total_execs": 0, "unique_crashes": 0}
        
        # Parse and return stats
        return self._parse_results()
    
    def _parse_results(self) -> Dict[str, Any]:
        """Parse AFL++ output and statistics."""
        stats = self._parse_stats_file()
        
        # Count crashes
        crash_count = 0
        if self.crashes_dir.exists():
            crash_count = len([
                f for f in self.crashes_dir.iterdir()
                if f.is_file() and f.name.startswith("id:")
            ])
        
        # Count queue (corpus growth)
        queue_count = 0
        if self.queue_dir.exists():
            queue_count = len([
                f for f in self.queue_dir.iterdir()
                if f.is_file() and f.name.startswith("id:")
            ])
        
        return {
            "total_execs": int(stats.get("execs_done", 0)),
            "unique_crashes": crash_count,
            "unique_hangs": int(stats.get("saved_hangs", 0)),
            "queue_size": queue_count,
            "coverage": self._parse_coverage(stats),
            "exec_speed": stats.get("execs_per_sec", "0"),
            "last_crash": stats.get("last_crash", "0"),
            "raw_stats": stats,
        }
    
    def _parse_stats_file(self) -> Dict[str, str]:
        """Parse AFL++ fuzzer_stats file."""
        stats = {}
        
        if not self.stats_file.exists():
            logger.warning(f"Stats file not found: {self.stats_file}")
            return stats
        
        try:
            with open(self.stats_file) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        key, value = line.split(":", 1)
                        stats[key.strip()] = value.strip()
        except Exception as e:
            logger.warning(f"Failed to parse stats file: {e}")
        
        return stats
    
    def _parse_coverage(self, stats: Dict[str, str]) -> float:
        """Parse bitmap coverage from stats."""
        bitmap_cvg = stats.get("bitmap_cvg", "0%")
        try:
            return float(bitmap_cvg.replace("%", ""))
        except ValueError:
            return 0.0
    
    def get_crash_inputs(self) -> List[Path]:
        """Get list of crash input files."""
        if not self.crashes_dir.exists():
            return []
        
        crashes = [
            f for f in self.crashes_dir.iterdir()
            if f.is_file() and f.name.startswith("id:")
        ]
        
        return sorted(crashes)
    
    def get_queue_inputs(self) -> List[Path]:
        """Get list of queue (interesting) input files."""
        if not self.queue_dir.exists():
            return []
        
        queue = [
            f for f in self.queue_dir.iterdir()
            if f.is_file() and f.name.startswith("id:")
        ]
        
        return sorted(queue)


def check_afl_available() -> bool:
    """Check if AFL++ is installed and available."""
    try:
        result = subprocess.run(
            ["afl-fuzz", "--help"],
            capture_output=True,
            timeout=5
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
