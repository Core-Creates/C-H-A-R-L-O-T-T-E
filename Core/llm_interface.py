"""
llm_interface.py

Handles all interaction between CHARLOTTE and the configured LLM backend.
Supports OpenAI, Hugging Face, and other APIs for task-based prompting.
"""

import os
import json
from typing import Optional

import openai  # You can switch this to Hugging Face or LM Studio later
from core.config import CHARLOTTE_CONFIG


# Load API keys or use environment variables
openai.api_key = CHARLOTTE_CONFIG.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))


def format_prompt(task: str, context: str, goal: str) -> str:
    """
    Creates a task-specific prompt for the LLM.
    """
    return f"""
    [CHARLOTTE MODE: {task.upper()}]

    CONTEXT:
    {context}

    GOAL:
    {goal}

    Provide a detailed, actionable response.
    """


def query_llm(task: str, context: str, goal: str, model: str = "gpt-4") -> str:
    """
    Sends a prompt to the LLM and returns the response.
    """
    prompt = format_prompt(task, context, goal)
    
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
        )
        return response["choices"][0]["message"]["content"].strip()

    except Exception as e:
        return f"[LLM ERROR]: {str(e)}"


# Example usage
if __name__ == "__main__":
    # Simple local test
    task = "binary_analysis"
    context = "Disassembled main function from stripped ELF shows suspicious XOR loop"
    goal = "Explain what this function is likely doing and how to reverse it"

    output = query_llm(task, context, goal)
    print("\n🔍 CHARLOTTE'S INSIGHT:\n", output)
