# patcher.py
#
# This file sets up an agentic LLM execution of the patcher components.

from patcher.rootcause import RootCauseAgent
from patcher.strategist import StrategistAgent
from patcher.swe import SWEAgent

def run():
    rootcauseagent = RootCauseAgent()
    strategistagent = StrategistAgent()
    sweagent = SWEAgent()

    # Example Inputs (will eventually be removed)
    project_name = "libfastparse"
    snippets = """
[fastparse.c:4] void parse_input(const char *input) {
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

    rca = rootcauseagent.analyze_vulnerability(project_name, snippets, stacktrace)
    strategy = strategistagent.select_strategy(project_name, rca, snippets)
    _ = sweagent.generate_patch(project_name, rca, snippets, strategy)
