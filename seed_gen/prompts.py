# prompts.py
#
# Contains all LLM prompts for seed generation. The LLM generates Python functions
# that produce seed bytes, making parsing more reliable.

SEED_INIT_SYSTEM_PROMPT = """
You are an expert fuzzing engineer creating seed inputs for a C/C++ program.
Your goal is to write Python functions that generate valid, diverse inputs to help a fuzzer explore different code paths.
"""

SEED_INIT_USER_PROMPT = """
You are generating seed inputs for fuzzing the following project:

<project_name>
{PROJECT_NAME}
</project_name>

<source_code>
{SOURCE_CODE}
</source_code>

<harness>
{HARNESS_CODE}
</harness>

Write {COUNT} Python functions that each generate a seed input as bytes.

IMPORTANT RULES:
1. Each function MUST have the signature: `def gen_seed_X() -> bytes` where X is a number/string
2. Each function MUST return a `bytes` object and remember you can only concatenate bytes or concatenate strings and encode to bytes or concatenate bytes with string converted to bytes
3. Functions must be DETERMINISTIC - no random, no time-based values
4. Only use the Python standard library
5. Keep seeds relatively small (under 1KB each)
6. Create at least {COUNT} diverse inputs that test different code paths

Analyze the source code to understand:
- How input is read (fread, scanf, argv, stdin, etc.)
- Expected input format (file format, protocol, text, binary)
- Any magic bytes, headers, or format markers
- Boundary conditions and edge cases
- Trace data flow and validation logic in EXTREME DETAIL written out step by step

Put ALL functions in a SINGLE markdown code block at the end.

Example output for an FTP server harness:
```python
def gen_seed_user() -> bytes:
    # user command
    username = "anonymous"
    user_cmd = "USER %s\r\n" % (username)
    return user_cmd.encode()

def gen_seed_pass() -> bytes:
    # pass command
    password = "mypassword"
    pass_cmd = "PASS %s\r\n" % (password)
    return pass_cmd.encode()
```

Now analyze the source code and generate {COUNT} seed functions:
"""

SEED_EXPLORE_SYSTEM_PROMPT = """
You are an expert fuzzing engineer creating targeted seed inputs.
Your goal is to write Python functions that generate inputs reaching a specific function in the program and getting full coverage of the function and its paths.
"""

SEED_EXPLORE_USER_PROMPT = """
You are generating seed inputs to reach a specific target function:

<project_name>
{PROJECT_NAME}
</project_name>

<target_function>
{TARGET_FUNCTION}
</target_function>

<target_function_code>
{TARGET_FUNCTION_CODE}
</target_function_code>

<full_source_code>
{SOURCE_CODE}
</full_source_code>

<harness>
{HARNESS_CODE}
</harness>

Write {COUNT} Python functions that generate seed inputs which will cause execution to reach the target function.

First, trace the path from entry point to target:
1. How is input read?
2. What parsing/validation happens?
3. What conditions lead to calling the target function?
- Trace data flow and validation logic in EXTREME DETAIL

IMPORTANT RULES:
1. Each function MUST have the signature: `def gen_seed_X() -> bytes` where X is a number/string
2. Each function MUST return a `bytes` object and remember you can only concatenate bytes or concatenate strings and encode to bytes or concatenate bytes with string converted to bytes
3. Functions must be DETERMINISTIC - no random values
4. Only use the Python standard library
5. Each function should take a different path to reach the target
6. Create at least {COUNT} diverse inputs that test different code paths

Put ALL functions in a SINGLE markdown code block at the end.

Example output for an FTP server harness:
```python
def gen_seed_user() -> bytes:
    # user command
    username = "anonymous"
    user_cmd = "USER %s\r\n" % (username)
    return user_cmd.encode()

def gen_seed_pass() -> bytes:
    # pass command
    password = "mypassword"
    pass_cmd = "PASS %s\r\n" % (password)
    return pass_cmd.encode()
```

Now analyze how to reach `{TARGET_FUNCTION}` and generate {COUNT} seed functions:
"""
