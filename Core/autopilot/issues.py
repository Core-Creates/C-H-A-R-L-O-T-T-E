from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass(frozen=True)
class Issue:
    title: str
    severity: str  # 'low' | 'medium' | 'high' | 'critical'
    details: Dict[str, Any]
    hint: Optional[str] = None
