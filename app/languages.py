"""專案語言偵測與依語言的風險彙總。

掃描完成後會走訪工作區，依副檔名／檔名辨識專案使用的語言，統計檔案數、
行數與大小；再依 findings 的檔案路徑把風險歸到對應語言。這份資料會存入
scan stats，供 API、Web UI 與 MCP 摘要使用。
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .config import EXCLUDE_DIRS, SEVERITIES, SKIP_EXTENSIONS

# language id -> (顯示名稱, 類別)
_LANGUAGE_META: dict[str, tuple[str, str]] = {
    "python": ("Python", "code"),
    "javascript": ("JavaScript", "code"),
    "typescript": ("TypeScript", "code"),
    "java": ("Java", "code"),
    "go": ("Go", "code"),
    "php": ("PHP", "code"),
    "ruby": ("Ruby", "code"),
    "rust": ("Rust", "code"),
    "csharp": ("C#", "code"),
    "c": ("C", "code"),
    "cpp": ("C++", "code"),
    "kotlin": ("Kotlin", "code"),
    "swift": ("Swift", "code"),
    "scala": ("Scala", "code"),
    "dart": ("Dart", "code"),
    "objectivec": ("Objective-C", "code"),
    "lua": ("Lua", "code"),
    "perl": ("Perl", "code"),
    "r": ("R", "code"),
    "visualbasic": ("Visual Basic", "code"),
    "fsharp": ("F#", "code"),
    "haskell": ("Haskell", "code"),
    "elixir": ("Elixir", "code"),
    "erlang": ("Erlang", "code"),
    "clojure": ("Clojure", "code"),
    "groovy": ("Groovy", "code"),
    "julia": ("Julia", "code"),
    "zig": ("Zig", "code"),
    "nim": ("Nim", "code"),
    "crystal": ("Crystal", "code"),
    "ocaml": ("OCaml", "code"),
    "fortran": ("Fortran", "code"),
    "cobol": ("COBOL", "code"),
    "solidity": ("Solidity", "code"),
    "assembly": ("Assembly", "code"),
    "shell": ("Shell", "shell"),
    "powershell": ("PowerShell", "shell"),
    "sql": ("SQL", "query"),
    "html": ("HTML", "markup"),
    "css": ("CSS", "markup"),
    "vue": ("Vue", "markup"),
    "svelte": ("Svelte", "markup"),
    "xml": ("XML", "markup"),
    "markdown": ("Markdown", "markup"),
    "dockerfile": ("Dockerfile", "config"),
    "makefile": ("Makefile", "config"),
    "cmake": ("CMake", "config"),
    "terraform": ("Terraform", "config"),
    "yaml": ("YAML", "config"),
    "json": ("JSON", "config"),
    "toml": ("TOML", "config"),
    "ini": ("INI", "config"),
    "protobuf": ("Protocol Buffers", "config"),
    "graphql": ("GraphQL", "config"),
    "other": ("其他／未知", "other"),
}

_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".phtml": "php",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
    ".csx": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".h++": "cpp",
    ".ino": "cpp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sc": "scala",
    ".dart": "dart",
    ".m": "objectivec",
    ".mm": "objectivec",
    ".lua": "lua",
    ".pl": "perl",
    ".pm": "perl",
    ".r": "r",
    ".vb": "visualbasic",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".fsi": "fsharp",
    ".hs": "haskell",
    ".lhs": "haskell",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".cljc": "clojure",
    ".groovy": "groovy",
    ".gradle": "groovy",
    ".jl": "julia",
    ".zig": "zig",
    ".nim": "nim",
    ".cr": "crystal",
    ".ml": "ocaml",
    ".mli": "ocaml",
    ".f": "fortran",
    ".f77": "fortran",
    ".f90": "fortran",
    ".f95": "fortran",
    ".f03": "fortran",
    ".cob": "cobol",
    ".cbl": "cobol",
    ".cpy": "cobol",
    ".sol": "solidity",
    ".asm": "assembly",
    ".s": "assembly",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "shell",
    ".ksh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".xhtml": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    ".vue": "vue",
    ".svelte": "svelte",
    ".xml": "xml",
    ".xsd": "xml",
    ".xsl": "xml",
    ".xslt": "xml",
    ".plist": "xml",
    ".md": "markdown",
    ".markdown": "markdown",
    ".mdx": "markdown",
    ".dockerfile": "dockerfile",
    ".mk": "makefile",
    ".cmake": "cmake",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".jsonc": "json",
    ".json5": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".proto": "protobuf",
    ".graphql": "graphql",
    ".gql": "graphql",
}

_FILENAME_LANGUAGE: dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "makefile",
    "gnumakefile": "makefile",
    "bsdmakefile": "makefile",
    "cmakelists.txt": "cmake",
    "cargo.lock": "toml",
    "gemfile": "ruby",
    "rakefile": "ruby",
    "podfile": "ruby",
    "vagrantfile": "ruby",
}

# 只把「程式碼」與腳本納入主要語言判定；設定、文件與資料檔仍會列出。
_PRIMARY_CATEGORIES = frozenset({"code", "shell", "query"})

_CATEGORY_NAMES = {
    "code": "程式碼",
    "shell": "腳本",
    "query": "查詢",
    "markup": "標記",
    "config": "設定",
    "other": "其他",
}

_SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def language_for_path(path: str | Path) -> str | None:
    """依檔名或副檔名回傳語言 id；無法辨識時回傳 None。"""

    name = Path(str(path)).name.lower()
    if name in _FILENAME_LANGUAGE:
        return _FILENAME_LANGUAGE[name]
    return _EXTENSION_LANGUAGE.get(Path(name).suffix.lower())


def language_name(language_id: str | None) -> str:
    if not language_id:
        return "未知"
    return _LANGUAGE_META.get(language_id, (language_id, "other"))[0]


def language_category(language_id: str | None) -> str:
    if not language_id:
        return "other"
    return _LANGUAGE_META.get(language_id, (language_id, "other"))[1]


def category_name(category: str | None) -> str:
    return _CATEGORY_NAMES.get(str(category or "other"), "其他")


def _count_lines(path: Path) -> int:
    lines = 0
    last = b""
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                lines += chunk.count(b"\n")
                last = chunk[-1:]
    except OSError:
        return 0
    if last and last != b"\n":
        lines += 1
    return lines


def _iter_source_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in EXCLUDE_DIRS and not (base / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = base / filename
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            yield path


def detect_languages(root: str | Path) -> dict[str, Any]:
    """走訪 root，回傳語言統計與主要語言。

    回傳結構可直接放進 scan stats；`percent` 以行數計算，沒有行數時改用 bytes。
    """

    root_path = Path(root).resolve()
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "lines": 0, "bytes": 0})

    for path in _iter_source_files(root_path):
        language_id = language_for_path(path)
        if language_id is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        entry = stats[language_id]
        entry["files"] += 1
        entry["bytes"] += size
        entry["lines"] += _count_lines(path)

    total_files = sum(entry["files"] for entry in stats.values())
    total_lines = sum(entry["lines"] for entry in stats.values())
    total_bytes = sum(entry["bytes"] for entry in stats.values())
    basis = "lines" if total_lines else "bytes"

    languages: list[dict[str, Any]] = []
    for language_id, entry in stats.items():
        name, category = _LANGUAGE_META.get(language_id, (language_id, "other"))
        if basis == "lines":
            percent = (entry["lines"] / total_lines * 100) if total_lines else 0.0
        else:
            percent = (entry["bytes"] / total_bytes * 100) if total_bytes else 0.0
        languages.append(
            {
                "id": language_id,
                "name": name,
                "category": category,
                "category_name": category_name(category),
                "files": entry["files"],
                "lines": entry["lines"],
                "bytes": entry["bytes"],
                "percent": round(percent, 1),
            }
        )

    languages.sort(key=lambda item: (-item["lines"], -item["bytes"], item["name"]))
    primary = next(
        (item for item in languages if item["category"] in _PRIMARY_CATEGORIES),
        languages[0] if languages else None,
    )

    return {
        "primary_language": primary["id"] if primary else None,
        "primary_language_name": primary["name"] if primary else None,
        "languages": languages,
        "total_files": total_files,
        "total_lines": total_lines,
        "total_bytes": total_bytes,
        "percent_basis": basis,
        "detected_languages": len(languages),
    }


def _field(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _normalize_language_stats(
    languages: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    entries: dict[str, dict[str, Any]] = {}
    primary: str | None = None
    if not languages:
        return entries, primary

    if isinstance(languages, Mapping):
        items = languages.get("languages") or []
        primary = languages.get("primary_language")
    else:
        items = list(languages)

    for item in items:
        language_id = str(item.get("id") or item.get("language") or "other")
        name, category = _LANGUAGE_META.get(language_id, (language_id, "other"))
        resolved_category = item.get("category") or category
        entries[language_id] = {
            "id": language_id,
            "name": item.get("name") or name,
            "category": resolved_category,
            "category_name": item.get("category_name") or category_name(resolved_category),
            "files": int(item.get("files") or 0),
            "lines": int(item.get("lines") or 0),
            "bytes": int(item.get("bytes") or 0),
            "percent": float(item.get("percent") or 0.0),
        }
    return entries, primary


def _risk_level(counts: Mapping[str, int]) -> str:
    for severity in SEVERITIES:
        if counts.get(severity, 0):
            return severity
    return "none"


def aggregate_language_risk(
    findings: Sequence[Any],
    languages: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    *,
    top_rules: int = 3,
) -> dict[str, Any]:
    """把 findings 依語言分組，回傳各語言的風險等級與熱門規則。

    `languages` 可傳 `detect_languages()` 的結果，讓沒有 findings 的語言也列出。
    findings 可為 `Finding` 物件或 API 回傳的 dict。
    """

    entries, primary = _normalize_language_stats(languages)
    severity_counts: dict[str, Counter[str]] = defaultdict(Counter)
    rule_counts: dict[str, Counter[str]] = defaultdict(Counter)
    rule_info: dict[str, dict[str, Any]] = {}

    for finding in findings:
        file_path = str(_field(finding, "file", "") or "")
        language_id = language_for_path(file_path) or "other"
        if language_id not in entries:
            name, category = _LANGUAGE_META.get(language_id, (language_id, "other"))
            entries[language_id] = {
                "id": language_id,
                "name": name,
                "category": category,
                "category_name": category_name(category),
                "files": 0,
                "lines": 0,
                "bytes": 0,
                "percent": 0.0,
            }

        severity = str(_field(finding, "severity", "info") or "info")
        rule_id = str(_field(finding, "rule_id", "unknown") or "unknown")
        severity_counts[language_id][severity] += 1
        rule_counts[language_id][rule_id] += 1
        rule_info.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": str(_field(finding, "message", "") or "")[:500],
            },
        )

    result_languages: list[dict[str, Any]] = []
    for language_id, entry in entries.items():
        counts = severity_counts.get(language_id, Counter())
        score = sum(_SEVERITY_WEIGHTS.get(sev, 0) * count for sev, count in counts.items())
        top = [
            {
                **rule_info.get(rule_id, {"rule_id": rule_id, "severity": "info", "message": ""}),
                "count": count,
            }
            for rule_id, count in sorted(
                rule_counts.get(language_id, Counter()).items(),
                key=lambda item: (-item[1], item[0]),
            )[:top_rules]
        ]
        result_languages.append(
            {
                **entry,
                "findings": sum(counts.values()),
                "severity_counts": {severity: counts.get(severity, 0) for severity in SEVERITIES},
                "risk_score": score,
                "risk_level": _risk_level(counts),
                "top_rules": top,
            }
        )

    result_languages.sort(
        key=lambda item: (
            -item["risk_score"],
            -item["findings"],
            -item["lines"],
            item["name"],
        )
    )

    if primary is None:
        primary = next(
            (
                item["id"]
                for item in result_languages
                if item["category"] in _PRIMARY_CATEGORIES
            ),
            result_languages[0]["id"] if result_languages else None,
        )

    risk_levels = Counter(item["risk_level"] for item in result_languages)
    return {
        "primary_language": primary,
        "primary_language_name": language_name(primary),
        "languages": result_languages,
        "total_findings": len(findings),
        "risk_levels": dict(risk_levels),
    }
