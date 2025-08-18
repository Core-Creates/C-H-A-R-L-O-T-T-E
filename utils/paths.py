# utils/paths.py
from pathlib import Path

# Prefer the real implementation at repo root if present.
# If you keep the real implementation at repo root:
#     from paths import display_path
# We import it under an internal name and delegate to it if available.
try:
    from paths import display_path as _external_display_path  # type: ignore[attr-defined]
except Exception:
    _external_display_path = None  # Fallback inline shim will be used


def display_path(path: str, base: str | None = None) -> str:
    """
    Return a short, forward-slashed path for console/report output.
    If base is provided, show the path relative to that base; otherwise to CWD.

    Notes:
      - If a top-level `paths.display_path` exists, we delegate to it.
      - Otherwise we use the safe internal implementation below (fallback inline shim).
    """
    # Delegate to external implementation if available
    if _external_display_path is not None:
        try:
            return _external_display_path(path, base)
        except Exception:
            # If external impl misbehaves, fall back to the internal shim
            pass

    # Fallback inline shim (internal implementation)
    try:
        p = Path(path).resolve()
        root = Path(base).resolve() if base else Path.cwd()
        rel = p.relative_to(root)
        return str(rel).replace("\\", "/")
    except Exception:
        # Fall back to the original string, normalized
        return str(path).replace("\\", "/")
