# fuzz-bizz

*We're in the fuzzing business!*

**fuzz-bizz** is a Cyber Reasoning System (CRS) using AI to automate vulnerability detection and patching! It is heavily inspired by Trail of Bits's Buttercup! This project was made for CMPSC 279: Advanced Topics in Security at UCSB.

Authors:
- Hugo Lin
- Steven Jiang
- Ved Pradhan

## How to Run

We are still at a very early stage in this project. However, after installing the repository and navigating to the directory, you can run what is currently available using this command:

```
python3 orchestrator.py
```

The default Ollama model we use is `deepseek-coder:6.7b-instruct-q4_K_M`. Should you prefer to use a different model, you may do so by running the following command:

```
python3 orchestrator.py -m llama3.2:latest
```

Should you wish to redirect the log outputs to a particular file, you may do so as follows:

```
python3 orchestrator.py -o path_to_log_file.txt
```
