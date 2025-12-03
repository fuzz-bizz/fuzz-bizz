# seed_gen module
#
# LLM-powered seed generation for fuzzing. Generates Python functions
# that produce seed inputs, making the process more reliable.

from seed_gen.seed_gen import run, generate_for_function

__all__ = ["run", "generate_for_function"]
