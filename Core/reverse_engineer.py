from core.code_reasoner import CodeReasoner

reasoner = CodeReasoner()

def suggest_function_purpose(snippet):
    if "[MASK]" not in snippet:
        print("[CHARLOTTE]: Add a [MASK] token to guess a missing piece.")
        return
    guesses = reasoner.guess_missing_token(snippet)
    print("[CHARLOTTE whispers]: It might be... " + " / ".join(guesses))
    