# patcher.py
#
# This file sets up an agentic LLM execution of the patcher components. It assumes that the project
# has already been downloaded to the project/ directory.

from patcher.qe import QualityEngineerAgent
from patcher.reflection import ReflectionAgent
from patcher.rootcause import RootCauseAgent
from patcher.strategist import StrategistAgent
from patcher.swe import SWEAgent
from shared.stringasxml import extract

def run():
    rootcauseagent = RootCauseAgent()
    strategistagent = StrategistAgent()
    sweagent = SWEAgent()
    qeagent = QualityEngineerAgent()
    reflectionagent = ReflectionAgent()

    # Example Inputs (will eventually be removed)
    project_name = "libfastparse"
    snippets = """
[project/fastparse.c:11] void parse_input(const char *input) {
    char buffer[16];
    printf("Parsing input...\n");
    strcpy(buffer, input);
    printf("Received: %s\n", buffer);
}
"""
    stacktrace = """
#0  0x00007ffff7a334bb in __strcpy_ssse3 () from /usr/lib/libc.so.6
#1  0x0000555555555152 in parse_input (input=0x7fffffffe8d0 "AAAAAA...") at fastparse.c:10
#2  0x00005555555551d4 in main (argc=2, argv=0x7fffffffe7c8) at fastparse.c:20
"""

    previous_patches = []
    previous_patches_list = []
    reflection = ""
    step = "root_cause_analysis"
    rca = ""
    strategy = ""
    patch = ""
    patch_list = []

    while True:

        if step == "root_cause_analysis":
            rca = rootcauseagent.analyze_vulnerability(project_name, snippets, stacktrace, reflection=reflection)
            step = "patch_strategy"

        if step == "patch_strategy":
            strategy = strategistagent.select_strategy(project_name, rca, snippets, reflection=reflection)

        patch = sweagent.generate_patch(project_name, rca, snippets, strategy, previous_patch=(previous_patches[-1] if previous_patches else ""), reflection=reflection)
        patch_list = extract(patch, "patch")
        previous_patches.append(patch)

        if not patch_list:
            reflection = reflectionagent.reflect_on_patch(rca, snippets, previous_patches, "creation_failed")
            step = extract(reflection, "next_component")
            if (step not in ["patch_strategy", "patch_generation"]):
                step = "root_cause_analysis"
            continue

        duplicate = False
        patch_set = set(patch_list)
        for prev_list in previous_patches_list:
            prev_set = set(prev_list)
            if (patch_set == prev_set):
                duplicate = True
                break

        if duplicate:
            reflection = reflectionagent.reflect_on_patch(rca, snippets, previous_patches, "duplicated")
            step = extract(reflection, "next_component")
            if (step not in ["patch_strategy", "patch_generation"]):
                step = "root_cause_analysis"
            continue

        previous_patches_list.append(patch_list)
        if not qeagent.apply_patch(patch_list):
            qeagent.revert_patch()
            reflection = reflectionagent.reflect_on_patch(rca, snippets, previous_patches, "apply_failed")
            step = extract(reflection, "next_component")
            if (step not in ["patch_strategy", "patch_generation"]):
                step = "root_cause_analysis"
            continue

        # TODO: Compile and Test agains Fuzzed Inputs
