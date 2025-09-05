# utils/text.py


def unique_dorks(dorks: list[str], max_items=10) -> list[str]:
    """
    Deduplicate, trim, and cap a list of Google Dorks or similar strings.
    """
    seen, out = set(), []
    for d in dorks:
        d = " ".join(d.split())  # collapse whitespace
        if d not in seen:
            out.append(d)
            seen.add(d)
        if len(out) >= max_items:
            break
    return out
