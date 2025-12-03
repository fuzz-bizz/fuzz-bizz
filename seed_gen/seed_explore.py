# seed_explore.py
#
# Generates seeds targeting specific functions identified by static analysis.
# Integrates with the heatmap to prioritize interesting code paths.

from patcher.agent import Agent
from seed_gen.prompts import SEED_EXPLORE_SYSTEM_PROMPT, SEED_EXPLORE_USER_PROMPT
from seed_gen.executor import extract_python_code, execute_seed_code, validate_seed_code

import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)


class SeedExploreAgent(Agent):
    """
    Agent that generates seeds targeting specific functions.
    
    Designed to work with static analysis heatmap:
    1. Heatmap identifies high-priority functions
    2. This agent generates inputs that reach those functions
    """
    
    def __init__(self):
        super().__init__()
        self.systemprompt = SEED_EXPLORE_SYSTEM_PROMPT
        self.name = "seed explore agent"
    
    def generate_seeds(self,
                       project_name: str,
                       source_code: str,
                       target_function: str,
                       harness_code: str = "",
                       count: int = 4) -> List[bytes]:
        """
        Generate seeds that target a specific function.
        
        Args:
            project_name: Name of the project
            source_code: Full source code
            target_function: Name of function to reach
            harness_code: Optional fuzz harness
            count: Number of seeds to generate
            
        Returns:
            List of targeted seed inputs
        """
        logger.info(f"{self.name} generating {count} seeds targeting '{target_function}'")
        
        # Extract the target function's code for context
        func_code = self._extract_function(source_code, target_function)
        
        # Ask LLM to generate targeted seed functions
        response = self.ask(
            SEED_EXPLORE_USER_PROMPT.format(
                PROJECT_NAME=project_name,
                SOURCE_CODE=source_code,
                TARGET_FUNCTION=target_function,
                TARGET_FUNCTION_CODE=func_code or f"// Function '{target_function}' not found - generate based on name and context",
                HARNESS_CODE=harness_code or "No harness provided",
                COUNT=count
            )
        )
        
        # Extract Python code from response
        code = extract_python_code(response)
        
        if not code:
            logger.error(f"Failed to extract Python code for target '{target_function}'")
            return []
        
        logger.debug(f"Extracted code:\n{code}")
        
        # Validate and execute
        if not validate_seed_code(code):
            logger.warning(f"Generated code for '{target_function}' failed validation")
            return []
        
        seeds = execute_seed_code(code)
        
        logger.info(f"{self.name} generated {len(seeds)} seeds for '{target_function}'")
        return seeds
    
    def _extract_function(self, source_code: str, func_name: str) -> Optional[str]:
        """
        Extract a function's source code using regex.
        
        This is a simplified approach - works for most C/C++ functions.
        """
        # Pattern to match C function definitions
        # Handles: return_type func_name(params) { ... }
        pattern = rf'(?:[\w\s\*]+\s+)?{re.escape(func_name)}\s*\([^)]*\)\s*\{{'
        
        match = re.search(pattern, source_code)
        if not match:
            logger.debug(f"Function '{func_name}' not found with pattern match")
            return None
        
        # Find matching closing brace
        start = match.start()
        brace_count = 0
        end = start
        in_function = False
        
        for i, char in enumerate(source_code[start:], start):
            if char == '{':
                brace_count += 1
                in_function = True
            elif char == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    end = i + 1
                    break
        
        if end > start:
            func_code = source_code[start:end]
            logger.debug(f"Extracted function '{func_name}': {len(func_code)} chars")
            return func_code
        
        return None
    
    def find_related_functions(self, source_code: str, target_function: str) -> List[str]:
        """
        Find functions that call or are called by the target function.
        
        Useful for understanding context when generating targeted seeds.
        """
        related = []
        
        # Find functions that call target_function
        caller_pattern = rf'(\w+)\s*\([^)]*\)\s*\{{[^}}]*{re.escape(target_function)}\s*\('
        callers = re.findall(caller_pattern, source_code, re.DOTALL)
        related.extend(callers)
        
        # Find functions called by target_function
        func_code = self._extract_function(source_code, target_function)
        if func_code:
            # Simple pattern to find function calls
            call_pattern = r'(\w+)\s*\('
            calls = re.findall(call_pattern, func_code)
            # Filter out keywords and common functions
            keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof'}
            related.extend([c for c in calls if c not in keywords and c != target_function])
        
        return list(set(related))
