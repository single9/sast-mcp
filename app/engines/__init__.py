"""引擎選擇與狀態描述。"""

from __future__ import annotations

from ..config import get_settings
from ..errors import EngineError
from ..models import EngineInfo
from .base import Engine, EngineResult
from .regex_engine import RegexEngine
from .semgrep_engine import SemgrepEngine

__all__ = ["Engine", "EngineError", "EngineInfo", "EngineResult", "describe_engines", "select_engine"]


def select_engine() -> Engine:
    settings = get_settings()
    mode = settings.engine
    semgrep = SemgrepEngine()
    regex = RegexEngine()

    if mode == "regex":
        return regex
    if mode == "semgrep":
        if not semgrep.available():
            raise EngineError(
                "找不到 semgrep 執行檔。請安裝 semgrep，或設定 SAST_ENGINE=regex 使用內建規則。"
            )
        return semgrep
    if mode != "auto":
        raise EngineError(f"未知的 SAST_ENGINE 值：{mode}（可用 auto / semgrep / regex）")

    return semgrep if semgrep.available() else regex


def describe_engines() -> list[EngineInfo]:
    semgrep = SemgrepEngine()
    regex = RegexEngine()
    engines = [semgrep, regex]
    try:
        active = select_engine().name
    except EngineError:
        active = None

    result: list[EngineInfo] = []
    for engine in engines:
        available = engine.available()
        result.append(
            EngineInfo(
                name=engine.name,
                description=engine.description,
                available=available,
                active=engine.name == active,
                version=engine.version() if available else None,
            )
        )
    return result
