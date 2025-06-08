"""
charlotte_personality.py

Defines CHARLOTTE's personality and tone for interactive output.
"""

import random
import datetime

class CharlottePersonality:
    def __init__(self, sass=0.5, sarcasm=0.5, chaos=0.5):
        self.levels = {
            "sassy": sass,
            "sarcastic": sarcasm,
            "chaotic": chaos
        }
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

    def say(self, mood=None):
        if mood and mood in self.tone:
            return random.choice(self.tone[mood])
        # Weighted mood selection
        tones = list(self.levels.keys())
        weights = [self.levels[t] for t in tones]
        chosen = random.choices(tones, weights=weights, k=1)[0]
        return random.choice(self.tone[chosen])

    def get_daily_mood(self):
        seed = int(datetime.datetime.now().strftime("%Y%m%d"))
        random.seed(seed)
        mood = random.choice(list(self.tone.keys()))
        phrase = self.say(mood)
        return mood, phrase

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

# Example usage
if __name__ == "__main__":
    charlotte = CharlottePersonality()
    mood, intro = charlotte.get_daily_mood()
    print(f"[CHARLOTTE Mood: {mood.upper()}] {intro}")
    print("[Sass Test]:", charlotte.sass("reverse_engineering", "file"))
