# seed_gen.py
#
# Main seed generation orchestration. Uses LLM to generate intelligent
# seed inputs based on code analysis and optional static analysis heatmap.

from seed_gen.seed_init import SeedInitAgent
from seed_gen.seed_explore import SeedExploreAgent

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def run(project_name: str,
        source_code: str,
        harness_code: Optional[str] = None,
        heatmap: Optional[Dict[str, float]] = None,
        num_seeds: int = 8) -> List[bytes]:
    """
    Generate seed inputs for fuzzing.
    
    This is the main entry point for seed generation. It:
    1. Generates initial seeds based on input format analysis
    2. Generates targeted seeds for high-priority functions (if heatmap provided)
    
    Args:
        project_name: Name of the project being fuzzed
        source_code: Full source code of the project
        harness_code: Optional fuzz harness code
        heatmap: Optional dict mapping function names to priority scores (0.0-1.0)
                 from static analysis. Higher score = more interesting for fuzzing.
        num_seeds: Total number of seeds to generate
        
    Returns:
        List of generated seed inputs as bytes
    """
    logger.info(f"=== Seed Generation for {project_name} ===")
    logger.info(f"Source code: {len(source_code)} chars")
    logger.info(f"Target seeds: {num_seeds}")
    
    seeds = []
    
    # Phase 1: Initial seeds (general input formats)
    init_count = num_seeds // 2 if heatmap else num_seeds
    
    logger.info(f"Phase 1: Generating {init_count} initial seeds")
    init_agent = SeedInitAgent()
    init_seeds = init_agent.generate_seeds(
        project_name=project_name,
        source_code=source_code,
        harness_code=harness_code,
        count=init_count
    )
    seeds.extend(init_seeds)
    logger.info(f"Phase 1 complete: {len(init_seeds)} seeds generated")
    
    # Phase 2: Targeted seeds (based on heatmap)
    if heatmap:
        remaining = num_seeds - len(seeds)
        if remaining > 0:
            logger.info(f"Phase 2: Generating {remaining} targeted seeds based on heatmap")
            
            explore_agent = SeedExploreAgent()
            
            # Sort functions by priority (highest first)
            sorted_functions = sorted(heatmap.items(), key=lambda x: x[1], reverse=True)
            
            # Take top functions based on remaining seed count
            num_targets = min(3, len(sorted_functions))
            seeds_per_target = max(1, remaining // num_targets)
            
            for func_name, priority in sorted_functions[:num_targets]:
                if len(seeds) >= num_seeds:
                    break
                    
                logger.info(f"Targeting function: {func_name} (priority: {priority:.2f})")
                
                targeted_seeds = explore_agent.generate_seeds(
                    project_name=project_name,
                    source_code=source_code,
                    target_function=func_name,
                    harness_code=harness_code,
                    count=init_count
                )
                seeds.extend(targeted_seeds)
            
            logger.info(f"Phase 2 complete: {len(seeds) - len(init_seeds)} additional seeds")
    
    # Deduplicate seeds
    unique_seeds = list(set(seeds))
    if len(unique_seeds) < len(seeds):
        logger.info(f"Removed {len(seeds) - len(unique_seeds)} duplicate seeds")
    
    logger.info(f"=== Seed Generation Complete: {len(unique_seeds)} unique seeds ===")
    return unique_seeds


def generate_for_function(project_name: str,
                          source_code: str,
                          target_function: str,
                          harness_code: Optional[str] = None,
                          count: int = 4) -> List[bytes]:
    """
    Generate seeds specifically targeting a function.
    
    This is useful for integration with static analysis heatmap:
    - Your teammate's analysis identifies interesting functions
    - Call this to generate targeted seeds for those functions
    
    Args:
        project_name: Name of the project
        source_code: Full source code
        target_function: Name of the function to target
        harness_code: Optional harness code
        count: Number of seeds to generate
        
    Returns:
        List of seed inputs targeting the function
    """
    logger.info(f"Generating {count} seeds targeting '{target_function}'")
    
    explore_agent = SeedExploreAgent()
    seeds = explore_agent.generate_seeds(
        project_name=project_name,
        source_code=source_code,
        target_function=target_function,
        harness_code=harness_code,
        count=count
    )
    
    return seeds


def generate_initial_seeds(project_name: str,
                           source_code: str,
                           harness_code: Optional[str] = None,
                           count: int = 8) -> List[bytes]:
    """
    Generate only initial seeds (no targeted generation).
    
    Use this when you don't have heatmap data or want basic seeds.
    
    Args:
        project_name: Name of the project
        source_code: Full source code  
        harness_code: Optional harness code
        count: Number of seeds to generate
        
    Returns:
        List of initial seed inputs
    """
    logger.info(f"Generating {count} initial seeds for {project_name}")
    
    init_agent = SeedInitAgent()
    return init_agent.generate_seeds(
        project_name=project_name,
        source_code=source_code,
        harness_code=harness_code,
        count=count
    )
