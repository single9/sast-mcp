"""Taint 規則載入與名稱比對。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .model import SinkRule

_GENERIC_RE = re.compile(r"<[^<>]*>")


def normalize_name(text: str) -> str:
    value = " ".join(str(text or "").split())
    if value.startswith("new "):
        value = value[4:]
    value = value.replace("::", ".")
    value = _GENERIC_RE.sub("", value)
    return value.strip()


def split_name(text: str) -> tuple[str, str, str]:
    """回傳 (完整名稱, 接收者, 最後一段)。"""

    full = normalize_name(text)
    if "." in full:
        receiver, tail = full.rsplit(".", 1)
    else:
        receiver, tail = "", full
    tail = tail.split("(")[0].strip()
    return full, receiver, tail


def _receiver_matches(receiver: str, hints: list[str]) -> bool:
    if not hints:
        return True
    lowered = receiver.lower()
    return any(hint.lower() in lowered for hint in hints)


def matches_pattern(
    pattern: str, full: str, receiver: str, tail: str, receivers: list[str]
) -> bool:
    pattern = normalize_name(pattern)
    if not pattern:
        return False
    if pattern.startswith("*."):
        if tail != pattern[2:]:
            return False
        return _receiver_matches(receiver, receivers)
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return full.startswith(prefix + ".") or receiver == prefix
    if "." in pattern:
        return full == pattern or full.endswith("." + pattern)
    return tail == pattern


def _language_patterns(table: dict[str, list[str]], language: str) -> list[str]:
    values = list(table.get(language, []))
    values.extend(table.get("*", []))
    return values


@dataclass
class RuleSet:
    sources: dict[str, list[str]]
    sanitizers: dict[str, list[str]]
    sinks: list[SinkRule]
    propagators: dict[str, dict[str, int]] = field(default_factory=dict)

    def source_for_call(self, language: str, call_name: str) -> bool:
        full, receiver, tail = split_name(call_name)
        for pattern in _language_patterns(self.sources, language):
            normalized = normalize_name(pattern)
            if not normalized.startswith("*.") and (
                full == normalized
                or full.startswith(normalized + ".")
                or full.startswith(normalized + "(")
            ):
                return True
            if matches_pattern(pattern, full, receiver, tail, []):
                return True
        return False

    def source_for_expr(self, language: str, expression: str) -> bool:
        normalized = normalize_name(expression)
        if not normalized:
            return False
        for pattern in _language_patterns(self.sources, language):
            pattern = normalize_name(pattern)
            if pattern.startswith("*."):
                # 屬性存取（例如 C# 的 req.Query）沒有呼叫名稱，
                # 因此改成比對運算式裡任何一段結尾符合的成員。
                suffix = pattern[2:]
                start = 0
                while True:
                    position = normalized.find("." + suffix, start)
                    if position < 0:
                        break
                    rest = normalized[position + 1 + len(suffix) :]
                    if not rest or rest[0] in ".[( ":
                        return True
                    start = position + 1
                continue
            if (
                normalized == pattern
                or normalized.startswith(pattern + ".")
                or normalized.startswith(pattern + "[")
                or normalized.startswith(pattern + "(")
            ):
                return True
            # argv[、args[ 這類「陣列存取」規則本身就帶結尾符號。
            if pattern.endswith(("[", "(")) and normalized.startswith(pattern):
                return True
        return False

    def sanitizer_for_call(self, language: str, call_name: str) -> bool:
        full, receiver, tail = split_name(call_name)
        for pattern in _language_patterns(self.sanitizers, language):
            if matches_pattern(pattern, full, receiver, tail, []):
                return True
        return False

    def sink_for_call(self, language: str, call_name: str) -> SinkRule | None:
        full, receiver, tail = split_name(call_name)
        for rule in self.sinks:
            patterns = rule.patterns.get(language, []) + rule.patterns.get("*", [])
            for pattern in patterns:
                if matches_pattern(pattern, full, receiver, tail, rule.receivers):
                    return rule
        return None

    def propagator_target(self, language: str, call_name: str) -> int | None:
        """回傳「這個函式會把污染寫進第幾個參數」；例如 sprintf 的第 0 個。"""

        full, receiver, tail = split_name(call_name)
        table = self.propagators.get(language, {})
        for pattern, target in table.items():
            if matches_pattern(pattern, full, receiver, tail, []):
                return target
        return None


@lru_cache(maxsize=1)
def load_rules(path: str | None = None) -> RuleSet:
    rules_path = Path(path) if path else Path(__file__).resolve().parent / "dataflow.yml"
    with rules_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    sinks: list[SinkRule] = []
    for item in data.get("sinks", []):
        patterns = {
            str(language): [str(value) for value in values]
            for language, values in (item.get("patterns") or {}).items()
        }
        sinks.append(
            SinkRule(
                kind=str(item["kind"]),
                cwe=str(item.get("cwe", "")),
                severity=str(item.get("severity", "high")),
                message=str(item.get("message", item["kind"])),
                patterns=patterns,
                receivers=[str(value) for value in item.get("receivers", [])],
            )
        )

    return RuleSet(
        sources={
            str(language): [str(value) for value in values]
            for language, values in (data.get("sources") or {}).items()
        },
        sanitizers={
            str(language): [str(value) for value in values]
            for language, values in (data.get("sanitizers") or {}).items()
        },
        sinks=sinks,
        propagators={
            str(language): {str(name): int(target) for name, target in values.items()}
            for language, values in (data.get("propagators") or {}).items()
        },
    )
