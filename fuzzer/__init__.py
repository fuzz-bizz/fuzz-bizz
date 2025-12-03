# fuzzer module
#
# AFL++ based fuzzer wrapper for fuzz-bizz.
# Provides a simple interface for compiling, fuzzing, and processing crashes.

from fuzzer.fuzzer import run, FuzzResult, FuzzConfig

__all__ = ["run", "FuzzResult", "FuzzConfig"]
