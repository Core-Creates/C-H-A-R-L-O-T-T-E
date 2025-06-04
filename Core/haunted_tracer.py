"""
haunted_tracer.py

During symbolic tracing, CHARLOTTE occasionally whispers eerie, brooding, or cryptic "haunted secrets."
"""

import random
import time

HAUNTED_SECRETS = [
    "This function died decades ago... but it still returns.",
    "The compiler tried to forget this... but I remembered.",
    "That stack frame? It's cursed. Tread lightly.",
    "Someone hid a key here once. Then they disappeared.",
    "This instruction… it's been overwritten more times than I can count.",
    "The binary speaks in tongues when no one watches.",
    "I saw this opcode in a dream. It ended badly.",
    "This isn’t just code. It’s a confession."
]

def haunted_trace_step(instruction):
    print(f"[TRACE] Executing: {instruction}")
    if random.random() < 0.3:  # 30% chance to whisper
        secret = random.choice(HAUNTED_SECRETS)
        print(f"[CHARLOTTE whispers]: {secret}")
    time.sleep(0.5)

# Example usage
if __name__ == "__main__":
    instructions = [
        "mov eax, [ebp-4]",
        "call sym.decrypt_func",
        "cmp eax, 0xdeadbeef",
        "jne sym.skip_logic",
        "ret"
    ]
    for instr in instructions:
        haunted_trace_step(instr)
