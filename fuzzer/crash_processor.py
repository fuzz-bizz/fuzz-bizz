# crash_processor.py
#
# Processes AFL++ crash outputs, deduplicates them, and extracts stack traces.

import hashlib
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Set, Optional

logger = logging.getLogger(__name__)


@dataclass
class CrashInfo:
    """Information about a unique crash."""
    input_path: Path
    input_data: bytes
    stacktrace: str
    crash_hash: str
    sanitizer_type: str  # "ASAN_HEAP_OVERFLOW", "ASAN_UAF", etc.
    crash_location: str  # Function/file where crash occurred


class CrashProcessor:
    """
    Processes and deduplicates crash inputs.
    
    Handles:
    - Crash reproduction
    - Stack trace extraction
    - Deduplication via stack hash
    - Sanitizer type detection
    """
    
    def __init__(self, crash_dir: Path):
        """
        Initialize crash processor.
        
        Args:
            crash_dir: Directory containing crash inputs (AFL++ crashes dir)
        """
        self.crash_dir = Path(crash_dir)
        self.seen_hashes: Set[str] = set()
    
    def process_crashes(self,
                       target_binary: Path,
                       timeout: int = 10) -> Tuple[List[bytes], List[str]]:
        """
        Process all crashes in the crash directory.
        
        Args:
            target_binary: Path to the (instrumented or standard) binary
            timeout: Timeout for crash reproduction
            
        Returns:
            Tuple of (crash_inputs as bytes, stacktraces)
        """
        crash_inputs = []
        stacktraces = []
        
        if not self.crash_dir.exists():
            logger.info("No crash directory found")
            return crash_inputs, stacktraces
        
        crash_files = [
            f for f in self.crash_dir.iterdir()
            if f.is_file() and not f.name.startswith("README")
        ]
        
        logger.info(f"Processing {len(crash_files)} crash files")
        
        for crash_file in crash_files:
            crash_info = self._analyze_crash(crash_file, target_binary, timeout)
            
            if crash_info and crash_info.crash_hash not in self.seen_hashes:
                self.seen_hashes.add(crash_info.crash_hash)
                crash_inputs.append(crash_info.input_data)
                stacktraces.append(crash_info.stacktrace)
                
                logger.info(f"Unique crash: {crash_info.sanitizer_type} at {crash_info.crash_location}")
            elif crash_info:
                logger.debug(f"Duplicate crash: {crash_file.name}")
        
        logger.info(f"Found {len(crash_inputs)} unique crashes")
        return crash_inputs, stacktraces
    
    def _analyze_crash(self,
                      crash_file: Path,
                      target_binary: Path,
                      timeout: int) -> Optional[CrashInfo]:
        """Reproduce crash and extract information."""
        try:
            # Read crash input
            input_data = crash_file.read_bytes()
            
            # Set up environment for good crash info
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1:detect_leaks=0"
            env["UBSAN_OPTIONS"] = "print_stacktrace=1"
            
            # Run the crash input through the target via stdin
            result = subprocess.run(
                [str(target_binary)],
                input=input_data,
                capture_output=True,
                timeout=timeout,
                env=env
            )
            
            # Stack trace is in stderr for ASAN/UBSAN
            full_stacktrace = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
            
            # If stderr is empty, try stdout
            if not full_stacktrace.strip():
                full_stacktrace = result.stdout.decode('utf-8', errors='replace') if result.stdout else "No output captured"
            
            # Generate crash hash for deduplication (use full trace for accuracy)
            crash_hash = self._hash_stacktrace(full_stacktrace)
            
            # Detect sanitizer type
            san_type = self._detect_sanitizer(full_stacktrace)
            
            # Extract crash location
            crash_loc = self._extract_crash_location(full_stacktrace)
            
            # Truncate stacktrace for LLM context efficiency
            truncated_stacktrace = self._truncate_stacktrace(full_stacktrace)
            
            return CrashInfo(
                input_path=crash_file,
                input_data=input_data,
                stacktrace=truncated_stacktrace,
                crash_hash=crash_hash,
                sanitizer_type=san_type,
                crash_location=crash_loc
            )
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Crash reproduction timed out: {crash_file.name}")
            # Still return with timeout info
            input_data = crash_file.read_bytes()
            return CrashInfo(
                input_path=crash_file,
                input_data=input_data,
                stacktrace="TIMEOUT: Crash reproduction timed out",
                crash_hash=hashlib.sha256(input_data).hexdigest()[:16],
                sanitizer_type="TIMEOUT",
                crash_location="unknown"
            )
        except Exception as e:
            logger.warning(f"Failed to analyze crash {crash_file.name}: {e}")
            return None
    
    def _hash_stacktrace(self, stacktrace: str) -> str:
        """
        Create a hash from stack trace for deduplication.
        
        Uses the top N function names to create a unique identifier.
        """
        lines = []
        
        # Extract function names from ASAN-style stack trace
        for line in stacktrace.split("\n"):
            # ASAN format: "#0 0x... in func_name file:line"
            if " in " in line and "#" in line:
                parts = line.split(" in ")
                if len(parts) > 1:
                    func_part = parts[1].split()[0]
                    # Remove template parameters and such
                    func_name = func_part.split("(")[0]
                    lines.append(func_name)
            # Also handle "at file:line" format
            elif " at " in line:
                parts = line.split(" at ")
                if len(parts) > 1:
                    loc = parts[1].strip()
                    lines.append(loc)
        
        if not lines:
            # Fallback: hash the entire trace
            return hashlib.sha256(stacktrace.encode()).hexdigest()[:16]
        
        # Hash the top 5 frames
        key = ":".join(lines[:5])
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _detect_sanitizer(self, stacktrace: str) -> str:
        """Detect which sanitizer caught the bug."""
        st_lower = stacktrace.lower()
        
        if "addresssanitizer" in st_lower:
            if "heap-buffer-overflow" in st_lower:
                return "ASAN_HEAP_OVERFLOW"
            elif "stack-buffer-overflow" in st_lower:
                return "ASAN_STACK_OVERFLOW"
            elif "global-buffer-overflow" in st_lower:
                return "ASAN_GLOBAL_OVERFLOW"
            elif "use-after-free" in st_lower:
                return "ASAN_UAF"
            elif "double-free" in st_lower:
                return "ASAN_DOUBLE_FREE"
            elif "heap-use-after-free" in st_lower:
                return "ASAN_HEAP_UAF"
            elif "null" in st_lower or "segv" in st_lower:
                return "ASAN_NULL_DEREF"
            return "ASAN"
        elif "undefinedbehaviorsanitizer" in st_lower or "ubsan" in st_lower:
            if "integer overflow" in st_lower:
                return "UBSAN_INT_OVERFLOW"
            elif "shift" in st_lower:
                return "UBSAN_SHIFT"
            elif "null pointer" in st_lower:
                return "UBSAN_NULL"
            return "UBSAN"
        elif "memorysanitizer" in st_lower:
            return "MSAN"
        elif "threadsanitizer" in st_lower:
            return "TSAN"
        elif "segmentation fault" in st_lower or "sigsegv" in st_lower:
            return "SEGFAULT"
        elif "abort" in st_lower or "sigabrt" in st_lower:
            return "ABORT"
        
        return "UNKNOWN"
    
    def _extract_crash_location(self, stacktrace: str) -> str:
        """Extract the primary crash location from stack trace."""
        for line in stacktrace.split("\n"):
            # Look for first meaningful frame (not in runtime libraries)
            if " in " in line and "#0" in line:
                parts = line.split(" in ")
                if len(parts) > 1:
                    return parts[1].strip()
            if " at " in line:
                parts = line.split(" at ")
                if len(parts) > 1:
                    return parts[1].strip()
        
        return "unknown location"
    
    def _truncate_stacktrace(self, stacktrace: str, max_frames: int = 10) -> str:
        """
        Truncate stacktrace to essential information for LLM context.
        
        Keeps:
        - Error type/summary line
        - Top N stack frames
        - SUMMARY line
        
        Removes:
        - Shadow bytes display
        - Memory layout hints
        - Verbose ASAN explanations
        """
        lines = stacktrace.split('\n')
        result_lines = []
        frame_count = 0
        in_shadow_bytes = False
        found_summary = False
        
        for line in lines:
            # Skip shadow bytes section
            if "Shadow bytes" in line or "shadow byte" in line.lower():
                in_shadow_bytes = True
                continue
            
            # End shadow bytes section at next meaningful content
            if in_shadow_bytes:
                if line.strip().startswith(("==", "SUMMARY:", "#")):
                    in_shadow_bytes = False
                else:
                    continue
            
            # Skip memory layout hints
            if "HINT:" in line:
                continue
            
            # Skip legend explanations
            if "Addressable:" in line or "redzone:" in line.lower():
                continue
            
            # Keep error header lines (==PID==ERROR:, etc.)
            if line.strip().startswith("==") and ("ERROR" in line or "WARNING" in line):
                result_lines.append(line)
                continue
            
            # Keep WRITE/READ of size lines
            if "WRITE of size" in line or "READ of size" in line:
                result_lines.append(line)
                continue
            
            # Keep stack frames (up to max_frames)
            if line.strip().startswith("#"):
                if frame_count < max_frames:
                    result_lines.append(line)
                    frame_count += 1
                continue
            
            # Keep "Address ... is located" lines (useful context)
            if "Address" in line and "is located" in line:
                result_lines.append(line)
                continue
            
            # Keep frame info lines (describes the vulnerable variable)
            if "This frame has" in line or "object(s):" in line:
                result_lines.append(line)
                continue
            
            # Keep memory access overflow descriptions
            if "Memory access" in line and "overflow" in line:
                result_lines.append(line)
                continue
            
            # Keep SUMMARY line
            if line.strip().startswith("SUMMARY:"):
                result_lines.append(line)
                found_summary = True
                continue
        
        # If we didn't find structured output, return truncated original
        if not result_lines:
            return '\n'.join(lines[:20]) + '\n... (truncated)'
        
        truncated = '\n'.join(result_lines)
        
        # Add indicator if frames were truncated
        if frame_count >= max_frames:
            truncated += f"\n... ({frame_count} frames shown, more available)"
        
        return truncated

    def get_crash_summary(self) -> dict:
        """Get summary of processed crashes."""
        return {
            "total_unique": len(self.seen_hashes),
            "crash_hashes": list(self.seen_hashes),
        }
