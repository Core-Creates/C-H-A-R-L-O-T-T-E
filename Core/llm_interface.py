
# ******************************************************************************************
# llm_interface.py
# Handles all interaction between CHARLOTTE and the configured LLM backend.
# Supports OpenAI (default), Hugging Face models, or local Transformers.
# ******************************************************************************************

import os
from core.config import CHARLOTTE_CONFIG

# ******************************************************************************************
# 🔌 Provider Bootstrap
# Conditionally load and initialize the chosen LLM provider (OpenAI, Hugging Face, etc.)
# ******************************************************************************************

# Load OpenAI if selected as the LLM backend
if CHARLOTTE_CONFIG["LLM_PROVIDER"] == "openai":
    import openai
    openai.api_key = CHARLOTTE_CONFIG.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))

# Load Hugging Face Transformers pipeline if selected
if CHARLOTTE_CONFIG["LLM_PROVIDER"] == "huggingface":
    from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
    import torch

    HF_MODEL_NAME = CHARLOTTE_CONFIG.get("HF_MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.1")
    tokenizer = AutoTokenizer.from_pretrained(HF_MODEL_NAME)
    model = AutoModelForCausalLM.from_pretrained(HF_MODEL_NAME, torch_dtype=torch.float16, device_map="auto")
    pipe = pipeline("text-generation", model=model, tokenizer=tokenizer)

# ******************************************************************************************
# 🧠 Prompt Formatting
# Constructs a structured prompt for the LLM based on task + context + goal
# ******************************************************************************************

def format_prompt(task: str, context: str, goal: str) -> str:
    """Creates a task-specific prompt for the LLM."""
    return f"""
[CHARLOTTE MODE: {task.upper()}]

CONTEXT:
{context}

GOAL:
{goal}

Respond with actionable intelligence.
"""

# ******************************************************************************************
# 🤖 Query Dispatcher
# Routes prompt to appropriate LLM backend and returns output string
# ******************************************************************************************

def query_llm(task: str, context: str, goal: str) -> str:
    """Routes the prompt to the correct LLM backend based on config."""
    prompt = format_prompt(task, context, goal)
    provider = CHARLOTTE_CONFIG["LLM_PROVIDER"].lower()

    if provider == "openai":
        try:
            response = openai.ChatCompletion.create(
                model=CHARLOTTE_CONFIG.get("OPENAI_MODEL", "gpt-4"),
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
            )
            return response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"[OPENAI ERROR]: {str(e)}"

    elif provider == "huggingface":
        try:
            output = pipe(prompt, max_new_tokens=500, do_sample=True, temperature=0.7)[0]["generated_text"]
            return output.replace(prompt, "").strip()  # Clean echo from pipeline
        except Exception as e:
            return f"[HF ERROR]: {str(e)}"

    else:
        return "[ERROR]: Unsupported LLM_PROVIDER specified in config."

# ******************************************************************************************
# 🧪 Example Usage (CLI Invocation)
# Used for standalone testing of CHARLOTTE's LLM interface logic
# ******************************************************************************************

if __name__ == "__main__":
    task = "reverse_engineering"
    context = "The binary contains a function that loops over a buffer using XOR with 0x5A"
    goal = "Describe what this function is doing and how to recover the original data."

    print("\n🔍 CHARLOTTE'S INSIGHT:\n")
    print(query_llm(task, context, goal))
# ******************************************************************************************
# End of llm_interface.py