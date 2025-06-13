# ******************************************************************************************
# roast_generator.py - CHARLOTTE's parting thoughts after a scan
# Provides personality-driven roast summaries based on plugin and mood.
# ******************************************************************************************

import random

ROAST_LINES = {
    "binary_strings": {
        "sassy": [
            "Those strings were about as subtle as glitter in a crime scene.",
            "I've seen cleaner binaries in a malware author’s recycle bin.",
            "If entropy were a personality trait, this file would be a diva."
        ],
        "brooding": [
            "The strings whisper secrets only entropy can scream.",
            "This binary reeks of forgotten intentions and silent screams.",
            "Darkness binds these encoded runes. Good luck sleeping now."
        ],
        "manic": [
            "OMG STRINGS! ENCRYPTED! ENCODED! This is better than caffeine!",
            "CHAOS detected! Encryptions, obfuscations, obliquely suspicious bits!",
            "What a mess — and I love it. Chaos is *so* in right now 💅"
        ],
        "apathetic": [
            "There were strings. Some had entropy. Wow.",
            "Scan’s done. You do what you want with that data.",
            "Entropy high. Cool story, bro."
        ],
        "default": [
            "Binary strings extracted. High entropy regions might be sus.",
            "Scan complete. Check the results and cry later.",
            "Suspicious sections flagged. Or not. I’m not your boss."
        ],
    },
    "port_scan": {
        "sassy": [
            "You just rang every digital doorbell in the neighborhood, didn’t you?",
            "Open ports? Oh honey, those are just open *invitations* to chaos.",
            "You found doors. Now see who left them unlocked."
        ],
        "brooding": [
            "So many open ports... each one a scar, a weakness.",
            "Every service tells a story — and most of them end badly.",
            "Ports are whispers. Some scream louder than others."
        ],
        "manic": [
            "Look at all the juicy open ports! It’s like Christmas!",
            "PORT 22? PORT 80? PORT 1337?? *squeals in Nmap*",
            "This network’s like a leaky faucet of data. I LOVE IT!"
        ],
        "apathetic": [
            "Ports open. Ports closed. Life is meaningless.",
            "They’re open. Or not. Whatever.",
            "Scan complete. You can look if you care."
        ],
        "default": [
            "Ports scanned. Vulnerabilities might be lurking behind them.",
            "Scan done. Services found. You know what to do.",
            "Results in. You might want to patch that."
        ]
    },
    "sql_injection": {
        "sassy": [
            "Those inputs are thirstier than your ex’s DMs.",
            "If this was a login form, it’s about to get ghosted.",
            "One quote away from an ‘oops all data!’ moment."
        ],
        "brooding": [
            "Every vulnerable form is a confession waiting to be extracted.",
            "SQLi isn’t just a bug — it’s a betrayal written in queries.",
            "They trusted user input. Fools."
        ],
        "manic": [
            "OMG WE CAN INJECT STUFF! 💉 LET’S BREAK EVERYTHING!",
            "Is it user input or a backstage pass to your database?!",
            "If this were a rave, SQLi would be the fire alarm!"
        ],
        "apathetic": [
            "Yeah, it’s injectable. Or not. Whatever.",
            "Malicious input? Seen worse.",
            "You could inject it. If you care."
        ],
        "default": [
            "SQL injection scan complete. Review inputs and sanitize everything.",
            "Check for exposed queries. Your DB deserves better.",
            "You’re one unescaped apostrophe away from doom."
        ]
    },
    "xss_scan": {
        "sassy": [
            "Cross-site scripting? Cute. Did you sanitize anything?",
            "I found more holes than your favorite gossip app.",
            "Your site’s basically a comment section with nukes."
        ],
        "brooding": [
            "Scripts from shadows... executing in silence.",
            "One echo, one script, and trust is shattered.",
            "Your site talks to strangers. That’s never safe."
        ],
        "manic": [
            "POPUP ALERTS! COOKIE THEFT! THIS IS SO FUN!",
            "Your browser’s about to get bamboozled. 🌪️",
            "Scripts here, scripts there, scripts everywhere!"
        ],
        "apathetic": [
            "Scripts run. Sites break. People cry.",
            "It’s vulnerable. Probably. Who cares.",
            "Another insecure webapp. Shocker."
        ],
        "default": [
            "XSS scan complete. Consider CSP and escaping output.",
            "Cross-site scripting is the art of making trust regret itself.",
            "Audit your forms. They’re gossiping behind your back."
        ]
    },
    # Add more plugins as needed
}

def get_summary_roast(task, mood):
    lines = ROAST_LINES.get(task, {})
    if mood in lines:
        return random.choice(lines[mood])
    return random.choice(lines.get("default", ["Scan complete. Proceed with caution."]))
