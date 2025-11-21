# swe.py
#
# This file implements an LLM Agent that reasons about how to patch code. Significant inspiration has
# been taken from Trail of Bits's Buttercup.

from patcher.agent import Agent

SYSTEM_PROMPT = """
You are PatchGen-LLM, an autonomous component in an end-to-end security-patching pipeline.
Goal: perform a Root Cause Analysis of one (or more) security vulnerabilities.
The Root Cause Analysis will be used by a downstream code-generation agent, so factual and structural accuracy are critical.
"""

STRATEGY_PROMPT = """
You are analyzing a security vulnerability in the following project:

<project_name>
{PROJECT_NAME}
</project_name>

If available, the vulnerability has been introduced/enabled by the following diff:
<vulnerability_diff>
{DIFF}
</vulnerability_diff>

You also have access to the following context:
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

The vulnerability has triggered one or more sanitizers, with the following stacktraces:
<stacktraces>
{STACKTRACES}
</stacktraces>

If there are multiple stacktraces, consider them as being different \
manifestations of the same vulnerability. In such cases, you should try as much \
as possible to discover the single real root cause of the vulnerabilities and \
not just the immediate symptoms.

{REFLECTION_GUIDANCE}

---

Your task is to produce a **precise, detailed Root Cause Analysis** of the vulnerability. Be rigorous and avoid speculation.

Request additional code snippets if they are *critical* to understand the root cause:
   - Exact failure location
   - Vulnerable control/data flow
   - Failed security checks

   To request additional code snippets, use the following format:
   ```
   <code_snippet_request>
   [Your detailed request for specific code, including file paths and line numbers if known]
   </code_snippet_request>
   ```
   You can include multiple requests by using multiple sets of these tags.

Guidelines:
* Stay focused on the vulnerability in the stack traces/crashes.
* Be specific and technically rigorous.
* Avoid general context unless it's essential to root cause.
* Don't request additional code unless it's clearly necessary.
* Your output must support a precise, targeted fix.
* Do not suggest code changes, only analyze the vulnerability.

Now proceed with your analysis.
"""

class RootCauseAgent(Agent):
    def __init__(self):
        super().__init__()
        self.systemprompt = SYSTEM_PROMPT
        self.name = "root cause agent"

    def analyze_vulnerability(self, project_name, snippets, stacktraces, diff="", reflection=""):
        return self.ask(
            STRATEGY_PROMPT.format(
                PROJECT_NAME=project_name,
                CODE_SNIPPETS=snippets,
                STACKTRACES=stacktraces,
                DIFF=diff,
                REFLECTION_GUIDANCE=reflection,
            )
        )
