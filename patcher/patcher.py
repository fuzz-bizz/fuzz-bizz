# patcher.py
#
# This file sets up an agentic LLM execution of the patcher components.

from patcher.strategist import StrategistAgent
from patcher.swe import SWEAgent

def run():
    sweagent = SWEAgent()
    strategistagent = StrategistAgent()

    project_name = "TestProject"
    rca = "The function parse_input() fails to check bounds before copying into a fixed-size buffer."
    snippets = """
[oblong.py:27] def parse_input(data):
    buf = [0] * 8
    for i in range(len(data)):
        buf[i] = data[i]  # vulnerability: no bounds check
    return buf
"""

    strategy = strategistagent.select_strategy(project_name, rca, snippets)

    _ = sweagent.generate_patch(project_name, rca, snippets, strategy)
