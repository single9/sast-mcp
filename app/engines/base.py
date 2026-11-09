"""偵測引擎共用介面。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding


@dataclass
class EngineResult:
    findings: list[Finding]
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)


class Engine(ABC):
    name: str = "engine"
    description: str = ""

    @abstractmethod
    def available(self) -> bool:
        """引擎是否可在此環境執行。"""

    def version(self) -> str | None:
        return None

    @abstractmethod
    def scan(self, root: Path, timeout: int) -> EngineResult:
        """掃描 root 目錄，回傳正規化後的結果。"""
