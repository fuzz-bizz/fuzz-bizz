# swe.py
#
# This file implements an LLM Agent template. Significant inspiration has been taken from Trail of
# Bits's Buttercup.

from shared.config import OLLAMA_MODEL

from ollama import Client
import logging

class Agent:
    def __init__(self):
        self.client = Client()
        self.systemprompt = ""
        self.history = []
        self.name = "agent"

    def ask(self, message):
        logging.info(f"{self.name} is being prompted")

        messages = [{"role": "system", "content": self.systemprompt}]
        messages += self.history
        messages.append({"role": "user", "content": message})

        response = self.client.chat(model=OLLAMA_MODEL, messages=messages)

        self.history.append({"role": "user", "content": message})
        self.history.append(
            {"role": "assistant", "content": response["message"]["content"]}
        )

        logging.info(f"{self.name} produced\n\n{response['message']['content']}\n")

        return response["message"]["content"]
