# compiler.py
#
# Handles compiling C/C++ code with AFL++ instrumentation for coverage-guided fuzzing.

import glob
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class InstrumentedCompiler:
    """
    Compiles C/C++ code with AFL++ instrumentation.
    
    Supports:
    - afl-clang-fast (preferred)
    - afl-clang-lto
    - afl-gcc (fallback)
    """
    
    def __init__(self, project_dir: Path):
        """
        Initialize compiler for a project.
        
        Args:
            project_dir: Path to project source directory
        """
        self.project_dir = Path(project_dir)
        self.build_dir = self.project_dir / "build_afl"
        
    def compile_with_afl(self,
                         target_name: str = "target",
                         sanitizers: List[str] = None,
                         extra_flags: List[str] = None) -> Optional[Path]:
        """
        Compile the project with AFL++ instrumentation.
        
        Args:
            target_name: Name of the output binary
            sanitizers: List of sanitizers ["address", "undefined"]
            extra_flags: Additional compiler flags
            
        Returns:
            Path to instrumented binary or None on failure
        """
        sanitizers = sanitizers or ["address"]
        extra_flags = extra_flags or []
        
        os.makedirs(self.build_dir, exist_ok=True)
        
        # Detect source files
        source_files = self._find_source_files()
        if not source_files:
            logger.error("No C/C++ source files found in project")
            return None
        
        logger.info(f"Found {len(source_files)} source files")
        
        # Detect AFL compiler
        compiler = self._detect_afl_compiler()
        if not compiler:
            logger.error("No AFL++ compiler found. Please install AFL++")
            return None
        
        logger.info(f"Using compiler: {compiler}")
        
        output_path = self.build_dir / target_name
        
        # Build command
        cmd = [compiler]
        
        # Add sanitizer flags
        for san in sanitizers:
            cmd.append(f"-fsanitize={san}")
        
        # Standard debug flags for good crash info
        cmd.extend([
            "-g",                      # Debug symbols
            "-O1",                     # Light optimization (required for some sanitizers)
            "-fno-omit-frame-pointer", # Better stack traces
        ])
        
        # Extra flags
        cmd.extend(extra_flags)
        
        # Add source files (relative to project_dir since cwd=project_dir)
        cmd.extend([str(f.relative_to(self.project_dir)) for f in source_files])
        
        # Output (also relative to project_dir)
        cmd.extend(["-o", str(output_path.relative_to(self.project_dir))])
        
        logger.info(f"Compiling: {' '.join(cmd)}")
        
        # Get the correct SDK path for macOS
        env = os.environ.copy()
        try:
            sdk_result = subprocess.run(
                ["xcrun", "--show-sdk-path"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if sdk_result.returncode == 0:
                sdk_path = sdk_result.stdout.strip()
                env["SDKROOT"] = sdk_path
                logger.debug(f"Using SDK: {sdk_path}")
        except Exception:
            pass  # Continue without setting SDKROOT
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=120,
                env=env
            )
            
            if result.returncode != 0:
                logger.error(f"Compilation failed:\n{result.stderr}")
                return None
            
            if result.stderr:
                logger.debug(f"Compiler warnings:\n{result.stderr}")
            
            logger.info(f"Successfully compiled: {output_path}")
            return output_path
            
        except subprocess.TimeoutExpired:
            logger.error("Compilation timed out")
            return None
        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return None
    
    def compile_standard(self,
                        target_name: str = "target",
                        sanitizers: List[str] = None) -> Optional[Path]:
        """
        Compile without AFL instrumentation (for crash reproduction).
        
        Args:
            target_name: Name of the output binary
            sanitizers: List of sanitizers
            
        Returns:
            Path to binary or None on failure
        """
        sanitizers = sanitizers or ["address"]
        
        os.makedirs(self.build_dir, exist_ok=True)
        
        source_files = self._find_source_files()
        if not source_files:
            return None
        
        # Use clang if available, else gcc
        compiler = self._detect_standard_compiler()
        output_path = self.build_dir / f"{target_name}_standard"
        
        cmd = [compiler]
        
        for san in sanitizers:
            cmd.append(f"-fsanitize={san}")
        
        cmd.extend(["-g", "-O1", "-fno-omit-frame-pointer"])
        
        # Add source files (relative to project_dir since cwd=project_dir)
        cmd.extend([str(f.relative_to(self.project_dir)) for f in source_files])
        
        # Output (also relative to project_dir)
        cmd.extend(["-o", str(output_path.relative_to(self.project_dir))])
        
        # Get the correct SDK path for macOS
        env = os.environ.copy()
        try:
            sdk_result = subprocess.run(
                ["xcrun", "--show-sdk-path"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if sdk_result.returncode == 0:
                sdk_path = sdk_result.stdout.strip()
                env["SDKROOT"] = sdk_path
        except Exception:
            pass  # Continue without setting SDKROOT
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=120,
                env=env
            )
            
            if result.returncode != 0:
                logger.error(f"Standard compilation failed:\n{result.stderr}")
                return None
            
            return output_path
            
        except Exception as e:
            logger.error(f"Standard compilation error: {e}")
            return None
    
    def _find_source_files(self) -> List[Path]:
        """Find all C/C++ source files in project."""
        patterns = ["*.c", "*.cpp", "*.cc", "*.cxx"]
        files = []
        
        for pattern in patterns:
            # Search in project dir and immediate subdirs
            files.extend(self.project_dir.glob(pattern))
            files.extend(self.project_dir.glob(f"*/{pattern}"))
            files.extend(self.project_dir.glob(f"src/{pattern}"))
        
        # Exclude build directories and test files
        excluded_dirs = {'build', 'build_afl', 'test', 'tests', '.git'}
        files = [
            f for f in files 
            if not any(ex in f.parts for ex in excluded_dirs)
        ]
        
        return files
    
    def _detect_afl_compiler(self) -> Optional[str]:
        """Detect available AFL++ compiler."""
        compilers = [
            "afl-clang-fast",    # Preferred - fastest
            "afl-clang-lto",     # LTO instrumentation
            "afl-clang",         # Standard clang wrapper
            "afl-gcc",           # GCC wrapper (fallback)
        ]
        
        for compiler in compilers:
            try:
                result = subprocess.run(
                    [compiler, "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return compiler
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        return None
    
    def _detect_standard_compiler(self) -> str:
        """Detect available standard C compiler."""
        compilers = ["clang", "gcc", "cc"]
        
        for compiler in compilers:
            try:
                result = subprocess.run(
                    [compiler, "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return compiler
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        return "gcc"  # Default fallback
