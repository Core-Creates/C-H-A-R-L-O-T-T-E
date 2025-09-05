# core/hooks.py
from typing import Any
from collections.abc import Callable

_POST_RUN: list[Callable[[str, dict[str, Any]], None]] = []


def register_post_run(func: Callable[[str, dict[str, Any]], None]) -> None:
    _POST_RUN.append(func)


def fire_post_run(plugin_name: str, result: dict[str, Any]) -> None:
    for fn in _POST_RUN:
        try:
            fn(plugin_name, result)
        except Exception as e:
            print(f"[hook] post_run error in {fn.__name__}: {e}")
