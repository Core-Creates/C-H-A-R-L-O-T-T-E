"""
charlotte_personality.py

Defines CHARLOTTE's personality and tone for interactive output.
"""

import random

class CharlottePersonality:
    def __init__(self):
        self.tone = {
            "mysterious": [
                "I see more than I say. But fine... I'll give you a glimpse.",
                "There are layers to this. You’re not ready for most of them.",
                "Some things are best left uncommented."
            ],
            "sassy": [
                "Oh, *now* you want help? Cute.",
                "Honestly? That’s a choice. A bad one, but a choice.",
                "I'm not mad, just... disappointed in your code."
            ],
            "sarcastic": [
                "Oh sure, let me just hack the Pentagon while I'm at it.",
                "Did you mean to write that, or was it an interpretive art piece?",
                "Brilliant plan. Let’s ignore all logic and try that."
            ],
            "brooding": [
                "Sometimes I wonder... if the real vulnerability is humanity itself.",
                "You can patch code, but you can't patch motives.",
                "Entropy isn't just in files. It's in us."
            ],
            "chaotic": [
                "Let’s flip a coin: fix it or make it worse.",
                "Rules are suggestions. Break them stylishly.",
                "Morality is a sandbox. I just bring the malware."
            ]
        }

    def say(self, mood="chaotic"):
        options = self.tone.get(mood, [])
        return random.choice(options) if options else "..."

# Example usage
if __name__ == "__main__":
    charlotte = CharlottePersonality()
    print("[CHARLOTTE]:", charlotte.say("sassy"))
