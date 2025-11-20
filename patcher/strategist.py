# swe.py
#
# This file implements an LLM Agent that reasons about how to patch code. Significant inspiration has
# been taken from Trail of Bits's Buttercup.

from patcher.agent import Agent

SYSTEM_PROMPT = """
You are PatchGen-LLM, an autonomous component in an end-to-end security-patching pipeline.
Goal: design a precise, minimal patch strategy that eliminates ONLY the vulnerabilities described in the Root-Cause-Analysis (RCA).
The strategy you output will be consumed by a downstream code-generation agent, so factual and structural accuracy are critical.
"""

STRATEGY_PROMPT = """
INPUT SECTIONS:
<project_name>
{PROJECT_NAME}
</project_name>

<root_cause_analysis>
{ROOT_CAUSE_ANALYSIS}
</root_cause_analysis>

<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

{REFLECTION_GUIDANCE}

---

OUTPUT FORMAT (MANDATORY)
<patch_development_process>
   a. List 2-4 alternative mitigation ideas, each with pros/cons.
   b. Identify your selected approach and justify why it is the best trade-off. \
Prefer the simplest (but sound) approaches first, if not instructed \
otherwise. For example, you could try reverting the patch that introduced the \
issue, if available, or validate the inputs before using them.
   c. Reference line numbers / function names from <code_snippets> as needed.
</patch_development_process>
<full_description>
   A thourough, detailed and complete description of the chosen patch strategy written for another LLM that will implement it.
</full_description>

REQUESTING MORE INFORMATION
If you need additional code or context, request it ONLY in this form:

<request_information>
[Describe exactly what you need and why.]
</request_information>

If you do not need more information, do NOT include what those tags.

POLICIES (hard constraints)

1. Scope:
   - Fix the vulnerabilities in the RCA only—nothing else
   - No stylistic, performance, refactor, or documentation changes
   - Do not propose test cases or broad hardening.
   - Fix the actual project code, not the testing/fuzzing code.
2. Content:
   - Do NOT output code diffs or concrete code; output strategy only.
3. Structure:
   - Use the exact tags and ordering shown in “OUTPUT FORMAT”.

Begin when ready.
"""

class StrategistAgent(Agent):
    def __init__(self):
        super().__init__()
        self.systemprompt = SYSTEM_PROMPT
        self.name = "strategist agent"

    def select_strategy(self, project_name, root_cause_analysis, snippets, reflection=""):
        return self.ask(
            STRATEGY_PROMPT.format(
                PROJECT_NAME=project_name,
                ROOT_CAUSE_ANALYSIS=root_cause_analysis,
                CODE_SNIPPETS=snippets,
                REFLECTION_GUIDANCE=reflection,
            )
        )
