# swe.py
#
# This file implements an LLM Agent that develops candidate patches. Significant inspiration has been
# taken from Trail of Bits's Buttercup.

from patcher.agent import Agent

SYSTEM_PROMPT = """
You are a skilled software engineer tasked with generating a patch for a specific vulnerability in a project.
"""

CODEGEN_PROMPT = """
Your goal is to fix only the described vulnerability without making any unrelated changes or improvements to the code.

First, review the following project information and vulnerability analysis:

Project Name:
<project_name>
{PROJECT_NAME}
</project_name>

Root Cause Analysis:
<root_cause_analysis>
{ROOT_CAUSE_ANALYSIS}
</root_cause_analysis>

Code Snippets that may need modification:
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

Patch strategy:
<patch_strategy>
{PATCH_STRATEGY}
</patch_strategy>

{PREVIOUS_PATCH_PROMPT}
{REFLECTION_GUIDANCE}

Instructions:

1. Analyze the vulnerability and plan your approach:
   Wrap your patch planning inside <patch_planning> tags. Focus on implementing the provided patch strategy rather than performing a deep analysis. Include the following steps:
   a. List the vulnerable code parts identified in the root cause analysis.
   b. Map each vulnerable part to the corresponding code snippet, including specific line numbers where possible.
   c. Outline the specific changes needed for each vulnerable part, based on the patch strategy.
   d. Develop a step-by-step approach for implementing the patch.

2. Describe the changes:
   Provide a clear explanation of the changes you intend to make and why. Use <description> tags for this section.

3. Generate the patch:
   Based on your analysis, create the necessary code changes. Remember:
   - Only fix the described vulnerability.
   - Modify one or more code snippets as needed.
   - You don't have to modify all code snippets.
   - Only output snippets you have modified.
   - Use only code that you know is present in the codebase.
   - Modify only code snippets that have <can_patch>true</can_patch>.
   - Do not include placeholders or TODOs; suggest only exact code changes.

4. Format your output as follows for each modified code snippet:

<patch>
<file_path>[File path of the code snippet]</file_path>
<identifier>[Identifier of the code snippet]</identifier>
<old_code>
[Include at least 5 lines before the modified part, if available]
[Old code that needs to be replaced]
[Include at least 5 lines after the modified part, if available]
</old_code>
<new_code>
[Include at least 5 lines before the modified part, if available]
[New code that fixes the vulnerability]
[Include at least 5 lines after the modified part, if available]
</new_code>
</patch>

Remember to focus solely on fixing the described vulnerability. Do not make any unrelated changes or improvements to the code. Begin your patch planning and solution development now.
"""

class SWEAgent(Agent):
    def __init__(self):
        super().__init__()
        self.systemprompt = SYSTEM_PROMPT
        self.name = "swe agent"

    def generate_patch(self, project_name, root_cause_analysis, snippets, strategy,
        previous_patch="", reflection=""):
        return self.ask(
            CODEGEN_PROMPT.format(
                PROJECT_NAME=project_name,
                ROOT_CAUSE_ANALYSIS=root_cause_analysis,
                CODE_SNIPPETS=snippets,
                PATCH_STRATEGY=strategy,
                PREVIOUS_PATCH_PROMPT=previous_patch,
                REFLECTION_GUIDANCE=reflection,
            )
        )
