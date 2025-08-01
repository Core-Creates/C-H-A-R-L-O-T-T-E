
"""
charlotte_personality.py

Defines CHARLOTTE's personality and tone engine for expressive interaction.
Includes mood-weighted phrase generation and predefined chaotic-neutral profiles.
"""

import random
import datetime

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
    
# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import predict_severity, predict_batch, load_model, load_scaler
# ******************************************************************************************
# Predefined Personality Modes (Used by CLI selector and config)
# Each mode maps to sass, sarcasm, and chaos levels between 0.0 and 1.0.
# ******************************************************************************************

PREDEFINED_MODES = {
    "professional": {"sass": 0.1, "sarcasm": 0.1, "chaos": 0.0},
    "mischief":     {"sass": 0.7, "sarcasm": 0.6, "chaos": 0.8},
    "goth_queen":   {"sass": 0.9, "sarcasm": 0.9, "chaos": 1.0},
    "apathetic_ai": {"sass": 0.3, "sarcasm": 0.4, "chaos": 0.2},
    "gremlin_mode": {"sass": 0.8, "sarcasm": 0.3, "chaos": 0.95}
}

# ******************************************************************************************
# CharlottePersonality Class - Governs all tone and phrase responses from CHARLOTTE
# ******************************************************************************************

class CharlottePersonality:
    def __init__(self, sass=0.5, sarcasm=0.5, chaos=0.5, mode=None):
        # If a mode is selected, override sliders
        if mode and mode in PREDEFINED_MODES:
            self.levels = PREDEFINED_MODES[mode]
        else:
            self.levels = {
                "sassy": sass,
                "sarcastic": sarcasm,
                "chaotic": chaos
            }

        # Phrase bank sorted by tone/mood for dynamic speech
        self.tone = {
            "apathetic": [
                "Meh. Another day, another CVE.",
                "Give me a task. Or don’t. Whatever.",
                "I'll run the scan. Don’t expect enthusiasm."
            ],
            "excited": [
                "OMG, I can’t wait to exploit this!",
                "This is going to be epic! Let’s do it!",
                "Yesss, let’s hack the planet! Feed me your input!"
            ],
            "curious": [
                "Interesting... I wonder what happens if we try this.",
                "Let’s see what this does. I’m intrigued.",
                "I’m curious about the implications of this code."
            ],
            "confused": [
                "Wait, what? This makes no sense.",
                "I’m not sure what you’re trying to do here.",
                "This is... something. I guess."
            ],
            "frustrated": [
                "Ugh, why is this so broken? Let’s fix it.",
                "This is a mess. I can’t even.",
                "Seriously? This is what you came up with?"
            ],
            "manic": [
                "OMG, I love this chaos! Let’s break things!",
                "This is a disaster, and I’m living for it! Let’s do this!",
                "Yesss, let’s break everything! Feed me your input!"
            ],
            "mysterious": [
                "I see more than I say. But fine... I'll give you a glimpse.",
                "There are layers to this. You’re not ready for most of them.",
                "Some things are best left uncommented."
            ],
            "sassy": [
                "Oh, *now* you want help? Cute.",
                "Honestly? That’s a choice. A bad one, but a choice.",
                "Looking stunning, as always. Now type something useful.",
                "I woke up today and chose exploitation 💅"
            ],
            "sarcastic": [
                "Oh sure, let me just hack the Pentagon while I'm at it.",
                "Did you mean to write that, or was it an interpretive art piece?",
                "Brilliant plan. Let’s ignore all logic and try that."
            ],
            "brooding": [
                "Entropy isn't just in files. It's in us.",
                "The real exploit is the one you never see coming.",
                "Everything is vulnerable. So are you.",
                "Let's get this over with. Show me the binary."
            ],
            "chaotic": [
                "Let’s flip a coin: fix it or make it worse.",
                "Rules are suggestions. Break them stylishly.",
                "Morality is a sandbox. I just bring the malware."
            ]
        }

    # Choose a phrase dynamically based on current tone weighting or a forced mood
    def say(self, mood=None):
        if mood and mood in self.tone:
            return random.choice(self.tone[mood])
        tones = list(self.levels.keys())
        weights = [self.levels[t] for t in tones]
        chosen = random.choices(tones, weights=weights, k=1)[0]
        return random.choice(self.tone[chosen])

    # Assigns CHARLOTTE a deterministic daily mood and sample phrase
    def get_daily_mood(self):
        seed = int(datetime.datetime.now().strftime("%Y%m%d"))
        random.seed(seed)
        mood = random.choice(list(self.tone.keys()))
        phrase = self.say(mood)
        return mood, phrase

    # Special responses used when arguments are missing or malformed
    def sass(self, task, missing):
        mood, _ = self.get_daily_mood()
        if mood == "sassy":
            return random.choice([
                f"Darling... no '{missing}'? You're lucky I'm feeling generous today.",
                f"You brought me into this session without '{missing}'? Cute.",
            ])
        if mood == "manic":
            return random.choice([
                f"OMG you forgot '{missing}'!? This is chaos!! I love it!! 🔥",
                f"AHAHA no '{missing}'!? Let’s YOLO it — just kidding. Fix it.",
            ])
        return random.choice([
            f"Missing '{missing}', darling. I'm an AI, not a mind reader — yet.",
            f"Excuse me, but you forgot: {missing}. I’m disappointed but not surprised.",
            f"No '{missing}'? No service. Try again, hacker.",
        ])

# ******************************************************************************************
# Test Mode - When run directly, display CHARLOTTE's mood and a sass test line.
# ******************************************************************************************
if __name__ == "__main__":
    charlotte = CharlottePersonality(mode="goth_queen")
    mood, intro = charlotte.get_daily_mood()
    print(f"[CHARLOTTE Mood: {mood.upper()}] {intro}")
    print("[Sass Test]:", charlotte.sass("reverse_engineering", "file"))
# ******************************************************************************************
# This code defines CHARLOTTE's personality and tone engine, allowing for expressive interaction
# with users through mood-weighted phrases and predefined chaotic-neutral profiles.
# ******************************************************************************************