# reflection.py
#
# This file implements an LLM Agent that evaluates what went wrong in the outputs
# of the other agents. This enables the agentic system to come up with better patch
# options, mimicking human analysis.

from patcher.agent import Agent

SYSTEM_PROMPT = """
You are an agent - please keep going until the user's query is completely resolved, before ending your turn and yielding back to the user. Only terminate your turn when you are sure that the problem is solved.
You MUST plan extensively before each function call, and reflect extensively on the outcomes of the previous function calls. DO NOT do this entire process by making function calls only, as this can impair your ability to solve the problem and think insightfully.

You are the Reflection Engine in an autonomous vulnerability patching system.
"""

REFLECTION_PROMPT = """
You are a security-focused reflection engine in an autonomous vulnerability patching system. Your primary task is to analyze why a patch failed and determine the best next steps to unblock other agents in the system.

CRITICAL: Your role is to prevent infinite loops and ensure forward progress. If you see repeated failures of the same type, you MUST redirect to a different component rather than continuing the same approach.

Your thinking should be thorough and so it's fine if it's very long. You can think step by step before and after each action you decide to take.

First, carefully review the following information about the failed patch attempt:

Existing root cause analysis:
<root_cause_analysis>
{ROOT_CAUSE_ANALYSIS}
</root_cause_analysis>

Code snippets used until now:
<code_snippets>
{CODE_SNIPPETS}
</code_snippets>

Previous patch attempts, excluding the last one ({N_PREVIOUS_ATTEMPTS}):
<previous_attempts>
{PREVIOUS_ATTEMPTS}
</previous_attempts>

Now, analyze the specific failure information:

Last patch attempt:
<last_patch_attempt>
{LAST_PATCH_ATTEMPT}
</last_patch_attempt>

Failure analysis:
<failure_analysis>
<failure_type>{FAILURE_TYPE}</failure_type>
<failure_data>
{FAILURE_DATA}
</failure_data>
</failure_analysis>

Additional context:
<extra_information>
{EXTRA_INFORMATION}
</extra_information>

Your task is to analyze the provided information and determine:
1. The specific reason the patch failed
2. Which category the failure falls into
3. What improvements could be made to the vulnerability fix
4. Whether the patch shows partial success
5. Any patterns identified across multiple failed attempts
6. What component should handle the next step and why

To ensure a thorough and transparent reflection process, work through your analysis *STEP BY STEP* in <analysis_breakdown> tags inside your thinking block.
Do not jump directly to conclusions, always follow the steps and provide a detailed analysis in the <analysis_breakdown> tags.
Follow these steps:

1. **Loop Detection Analysis**: FIRST, examine the previous attempts for patterns that indicate potential infinite loops:
   - Count how many times each component has been called recently
   - Identify if the same failure type is repeating (3+ times = loop risk)
   - Check if the same error messages or failure modes keep occurring
   - Look for oscillation between components without progress
   - If a loop is detected, you MUST break it by choosing a different component

2. **Failure Context Summary**: Summarize key points from each input section:
   - Last patch attempt: Focus on what was changed and why it failed
   - Root cause analysis: Identify the core vulnerability and its impact
   - Code snippets: Note relevant security-sensitive code sections
   - Previous attempts: Look for patterns in failed approaches
   - Failure analysis: Understand the specific failure mode
   - Extra information: Consider any additional context

3. **Evidence Extraction**: Extract and quote relevant information from each input section for each point of analysis. Focus on:
   - Security-critical code sections
   - Error messages and failure patterns
   - Previous patch attempts and their outcomes
   - Root cause analysis insights

4. **Failure Category Assessment**: For the failure category, consider arguments for each possible category:
   - incomplete_fix: The patch addresses part but not all of the vulnerability
   - wrong_approach: The patch strategy doesn't properly address the root cause
   - misunderstood_root_cause: The vulnerability analysis was incorrect
   - missing_code_snippet: Required code context is not available
   - build_error: Technical issues preventing patch application
   - regression_issue: The patch breaks existing functionality

5. **Failure Category Scoring**: Rate the likelihood of each failure category on a scale of 1-5, considering:
   - Security impact of each failure type
   - Evidence from error messages and code
   - Previous attempt patterns
   - Root cause analysis alignment

6. **Security Improvement Identification**: List at least 3 potential improvements for the vulnerability fix. Focus ONLY on security-related improvements:
   - Input validation and sanitization
   - Access control and authorization checks
   - Memory safety and bounds checking
   - Race condition prevention
   - Resource cleanup and error handling
   - Cryptographic implementation fixes
   - Secure communication protocols
   - Authentication mechanisms

7. **Pattern Analysis**: Create a numbered list of patterns across multiple failed attempts:
   - Similar error messages or failure modes
   - Repeated security check omissions
   - Common code paths or functions
   - Consistent failure categories
   - Related security mechanisms
   - Component call frequency and outcomes

8. **Component Selection Strategy**: For the next component, consider pros and cons for each available component based on:
   - Current failure mode and what type of intervention is needed
   - Available information and whether more context is required
   - Previous attempt history and which components have been tried recently
   - Security requirements and which component best addresses the vulnerability

9. **Component Suitability Scoring**: Rate each component's suitability on a scale of 1-5, considering:
   - Current failure mode
   - Available information
   - Previous attempt history
   - Security requirements
   - **CRITICAL**: Reduce score by 3 points if component was called in last 2 attempts with same failure type

10. **Information Gap Analysis**: Carefully consider if the next component might need additional information:
    - Required code snippets
    - Security context
    - Error details
    - Previous attempt data
    If critical information is missing, prioritize components that can gather this information.

11. **Loop Breaking Decision**: If you have identified a pattern across multiple failures:
    - If the same component failed 3+ times: MUST choose a different component
    - If recently called components haven't made progress: MUST try an alternative approach
    - If oscillating between components: MUST try a third option
    - Document the pattern and its implications for future attempts

12. **Progress Validation**: Before finalizing your decision:
    - Ensure the selected component can make meaningful progress
    - Verify you're not repeating a recently failed approach
    - Confirm the guidance addresses the core security vulnerability
    - Check that the path forward is different from recent attempts

After your analysis, generate a structured reflection result using the following format:

<reflection_result>
<failure_reason>[Provide a detailed and specific reason for why the patch failed, focusing on security implications]</failure_reason>
<failure_category>[Choose one: incomplete_fix, wrong_approach, misunderstood_root_cause, missing_code_snippet, build_error, regression_issue]</failure_category>
<pattern_identified>[Describe any patterns seen across multiple failures, including loop detection results, or state "No clear pattern identified" if none are apparent]</pattern_identified>
<next_component>[Select one of the available components, ensuring it breaks any detected loops]</next_component>
<component_guidance>[Provide detailed, specific, actionable guidance for the selected component. Focus on security requirements and concrete steps to address the vulnerability. If breaking a loop, explain why this approach is different. Also include an explanation of the patterns identified across multiple failures and how to fix them.]</component_guidance>
<partial_success>[True if the patch shows partial success, False if it is completely broken and should be discarded. If the next component guidance says to "improve the patch" or modify the patch in some way, then the patch is partially successful.]</partial_success>
</reflection_result>

The available components for the next step are:
<available_components>
root_cause_analysis
patch_strategy
patch_generation
</available_components>

Remember:
- **PRIORITY 1**: Prevent infinite loops - if same failure type occurs 3+ times, MUST change component
- **PRIORITY 2**: Focus ONLY on fixing the security vulnerability
- Do NOT suggest adding tests, logging, or refactoring code
- Do NOT suggest improvements unrelated to the security vulnerability
- Your analysis and guidance should be thorough and specific enough to help unblock other agents in the autonomous patching system
- Try to provide first simpler guidance and only if those do not work, provide more complex guidance
- Always prioritize security-critical fixes over other improvements
- Consider the full security context when analyzing failures
- Look for patterns that might indicate deeper security issues
- When breaking loops, clearly explain why the new approach is different and likely to succeed

Your final output should consist only of the structured reflection result and should not duplicate or rehash any of the work you did in the analysis breakdown.
"""

CREATION_FAILED_FAILURE_DATA = """The patch generation component could not generate a \
patch. This means it produced a patch that could not be parsed, it provided an \
old_code snippet that does not match what was available, it \
tried to patch a snippet that was not found in the codebase, or \
similar."""

CREATION_FAILED_EXTRA_INFORMATION = """The last few patch attempts all failed \
because the patch generation component could not generate a patch. This means it \
produced a patch that could not be parsed, or it tried to patch a snippet that \
was not found in the codebase, or a similar error. Reflect on the patch from a \
broader perspective to understand what went wrong. Consider looking for new code \
snippets or re-evaluating the root cause analysis."""

DUPLICATED_FAILURE_DATA = """The patch is a duplicate of a previous patch \
attempt that was already tried, so it will not work either."""

DUPLICATED_EXTRA_INFORMATION = """The last few patch attempts all failed \
because the patch generation component produced a duplicate patch. This means \
it produced a patch that is identical to a previous patch attempt that was \
already tried. Reflect on the patch from a broader perspective to understand \
what went wrong. Consider looking for new code snippets or re-evaluating the \
root cause analysis."""

APPLY_FAILED_FAILURE_DATA = """The patch could not be applied to the codebase. \
This means that when doing `patch -p1 < patch.patch`, it returned an error."""

APPLY_FAILED_EXTRA_INFORMATION = """The last few patch attempts all failed \
because the patch could not be applied to the codebase. This means that when \
doing `patch -p1 < patch.patch`, it returned an error. Reflect on the patch from \
a broader perspective to understand what went wrong. Consider providing better \
information to the patch generation component."""

BUILD_FAILED_FAILURE_DATA = """The patch could not be applied to the codebase. \
This means it could not be parsed, or it tried to patch a snippet that was \
not found in the codebase, or similar.

Build failure stdout:
```
{stdout}
```

Build failure stderr:
```
{stderr}
```
"""

BUILD_FAILED_EXTRA_INFORMATION = """The last few patch attempts all failed \
because the patched code could not be compiled. Reflect on the patch from a \
broader perspective to understand what went wrong. Consider looking for new \
code snippets or providing better information to the patch generation component."""

POV_FAILED_FAILURE_DATA = """The patch did not fix the vulnerability.

POV stdout:
```
{stdout}
```

POV stderr:
```
{stderr}
```
"""

POV_FAILED_EXTRA_INFORMATION = """The last few patch attempts all failed \
because the patch did not fix the vulnerability. Reflect on the patch from a \
broader perspective to understand what went wrong. Consider looking for new code \
snippets that might be relevant for the vulnerability or re-evaluate the root \
cause analysis."""

INFO_DICT = {
    "creation_failed": (CREATION_FAILED_FAILURE_DATA, CREATION_FAILED_EXTRA_INFORMATION),
    "duplicated": (DUPLICATED_FAILURE_DATA, DUPLICATED_EXTRA_INFORMATION),
    "apply_failed": (APPLY_FAILED_FAILURE_DATA, APPLY_FAILED_EXTRA_INFORMATION),
    "build_failed": (BUILD_FAILED_FAILURE_DATA, BUILD_FAILED_EXTRA_INFORMATION),
    "pov_failed": (POV_FAILED_FAILURE_DATA, POV_FAILED_EXTRA_INFORMATION)
}

class ReflectionAgent(Agent):
    def __init__(self):
        super().__init__()
        self.systemprompt = SYSTEM_PROMPT
        self.name = "reflection agent"

    def reflect_on_patch(self, root_cause_analysis, snippets, previous_attempts, failure_type, stdout="", stderr=""):
        data, info = INFO_DICT[failure_type]
        data = data.format(
            stdout=stdout,
            stderr=stderr
        )
        return self.ask(
            REFLECTION_PROMPT.format(
                ROOT_CAUSE_ANALYSIS=root_cause_analysis,
                CODE_SNIPPETS=snippets,
                N_PREVIOUS_ATTEMPTS=len(previous_attempts),
                PREVIOUS_ATTEMPTS="\n\n".join(previous_attempts),
                LAST_PATCH_ATTEMPT=(previous_attempts[-1] if previous_attempts else ""),
                FAILURE_TYPE=failure_type,
                FAILURE_DATA=data,
                EXTRA_INFORMATION=info
            )
        )
