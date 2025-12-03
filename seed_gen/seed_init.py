# seed_init.py
#
# Generates initial seed corpus by analyzing source code and producing
# Python functions that create valid input formats to bootstrap the fuzzer.

from patcher.agent import Agent
from seed_gen.prompts import SEED_INIT_SYSTEM_PROMPT, SEED_INIT_USER_PROMPT
from seed_gen.executor import extract_python_code, execute_seed_code, validate_seed_code

import logging
from typing import List

logger = logging.getLogger(__name__)


class SeedInitAgent(Agent):
    """
    Agent that generates initial seed inputs for fuzzing.
    
    Uses LLM to analyze source code and generate Python functions
    that produce diverse, valid inputs for the fuzzer.
    """
    
    def __init__(self):
        super().__init__()
        self.systemprompt = SEED_INIT_SYSTEM_PROMPT
        self.name = "seed init agent"
    
    def generate_seeds(self,
                       project_name: str,
                       source_code: str,
                       harness_code: str = "",
                       count: int = 8) -> List[bytes]:
        """
        Generate initial seed inputs by analyzing the source code.
        
        The LLM generates Python functions that produce seed bytes,
        which are then executed to get the actual seeds.
        
        Args:
            project_name: Name of the project
            source_code: Full source code of the project
            harness_code: Optional fuzz harness code
            count: Number of seeds to generate
            
        Returns:
            List of seed inputs as bytes
        """
        logger.info(f"{self.name} generating {count} initial seeds for {project_name}")
        
        # Ask LLM to generate seed functions
        response = self.ask(
            SEED_INIT_USER_PROMPT.format(
                PROJECT_NAME=project_name,
                SOURCE_CODE=source_code,
                HARNESS_CODE=harness_code or "No harness provided - analyze main() or input handling functions",
                COUNT=count
            )
        )
        
        # Extract Python code from response
        code = extract_python_code(response)
        
        if not code:
            logger.error("Failed to extract Python code from LLM response")
            logger.debug(f"Response was: {response[:500]}...")
            return self._fallback_seeds()
        
        logger.debug(f"Extracted code:\n{code}")
        
        # Validate the code
        if not validate_seed_code(code):
            logger.warning("Generated code failed validation, using fallback seeds")
            return self._fallback_seeds()
        
        # Execute to get seeds
        seeds = execute_seed_code(code)
        
        if not seeds:
            logger.warning("No seeds generated from code, using fallback seeds")
            return self._fallback_seeds()
        
        logger.info(f"{self.name} successfully generated {len(seeds)} seeds")
        return seeds
    
    def _fallback_seeds(self) -> List[bytes]:
        """Return basic fallback seeds if LLM generation fails."""
        logger.info("Using fallback seeds")
        return [
            b"",                          # Empty input
            b"A",                         # Single char
            b"AAAA",                      # Short string
            b"A" * 100,                   # Longer string
            b"\x00",                      # Null byte
            b"\x00" * 16,                 # Null bytes
            b"\xff" * 16,                 # Max bytes
            b"0",                         # Number as string
            b"-1",                        # Negative
            b"2147483647",                # INT_MAX
            b"Hello, World!\n",           # Basic text
            b"test\x00input",             # String with null
        ]
