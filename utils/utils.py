# ============================================================================
# core/utils.py
# Common utility functions used across CHARLOTTE
# ============================================================================

import hashlib
import random
import string

def generate_hash(input_str):
    return hashlib.sha256(input_str.encode()).hexdigest()

def random_id(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))