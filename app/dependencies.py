"""Cargo.lock 依賴漏洞掃描：解析 lockfile 後查詢 OSV。

這個模組刻意不依賴 Rust toolchain（cargo/rustc），因此容器只需要網路就能
檢查 crates.io 套件的已知漏洞。查詢失敗不會讓掃描失敗，只會在 warnings
留下訊息。
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config import EXCLUDE_DIRS, get_settings
from .models import Finding, normalize_severity

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

_MAX_BATCH = 500
_MAX_DETAIL_FETCHES = 200
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _iter_lockfiles(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        if "Cargo.lock" in filenames:
            path = Path(dirpath) / "Cargo.lock"
            if not path.is_symlink():
                found.append(path)
    return found


def _line_map(text: str) -> dict[tuple[str, str], int]:
    """建立 (name, version) -> 行號的對照，供 finding 定位。"""

    lines = text.splitlines()
    mapping: dict[tuple[str, str], int] = {}
    name: str | None = None
    name_line = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
            name_line = number
            continue
        match = re.match(r'^name\s*=\s*"([^"]+)"', stripped)
        if match:
            name = match.group(1)
            name_line = number
            continue
        match = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
        if match and name:
            mapping[(name, match.group(1))] = name_line
    return mapping


def parse_cargo_lock(path: Path) -> list[dict[str, Any]]:
    """回傳 registry 套件清單；workspace/path/git 套件不送 OSV。"""

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        data = tomllib.loads(text)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: {exc}") from exc

    lines = _line_map(text)
    packages: list[dict[str, Any]] = []
    for entry in data.get("package") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        source = entry.get("source") or ""
        if not name or not version:
            continue
        if "crates.io" not in str(source):
            continue
        packages.append(
            {
                "name": str(name),
                "version": str(version),
                "line": lines.get((str(name), str(version))),
                "source": str(source),
            }
        )
    return packages


def _roundup(value: float) -> float:
    integer = int(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """計算 CVSS v3.0/v3.1 base score；無法解析時回傳 None。"""

    if not vector.upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key.upper()] = value.upper()

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    scope = metrics.get("S", "U")
    if av is None or ac is None or ui is None or scope not in {"U", "C"}:
        return None

    pr_table = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    pr = pr_table[scope].get(metrics.get("PR", ""))
    confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("C", ""))
    integrity = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("I", ""))
    availability = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("A", ""))
    if pr is None or confidentiality is None or integrity is None or availability is None:
        return None

    iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def vulnerability_severity(vuln: dict[str, Any]) -> str:
    database = vuln.get("database_specific") or {}
    label = str(database.get("severity") or "").strip().lower()
    if label:
        return normalize_severity(label)

    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, (int, float)):
            return _severity_from_score(float(score))
        if isinstance(score, str):
            parsed = cvss3_base_score(score)
            if parsed is not None:
                return _severity_from_score(parsed)
    return "medium"


def _cwe_ids(vuln: dict[str, Any]) -> list[str]:
    database = vuln.get("database_specific") or {}
    values: list[str] = []
    raw = database.get("cwe_ids") or vuln.get("cwe_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    for item in raw:
        for match in _CWE_RE.findall(str(item)):
            cwe = match.upper()
            if cwe not in values:
                values.append(cwe)
    return values


def _fixed_versions(vuln: dict[str, Any], name: str) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("name") and str(package.get("name")) != name:
            continue
        for item in affected.get("ranges") or []:
            for event in item.get("events") or []:
                version = event.get("fixed")
                if version and version not in fixed:
                    fixed.append(str(version))
    return fixed


def _query_osv(
    packages: list[dict[str, Any]], api_url: str, timeout: int
) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    warnings: list[str] = []
    endpoint = api_url.rstrip("/") + "/v1/querybatch"

    for start in range(0, len(packages), _MAX_BATCH):
        chunk = packages[start : start + _MAX_BATCH]
        payload = {
            "queries": [
                {
                    "package": {"name": item["name"], "ecosystem": "crates.io"},
                    "version": item["version"],
                }
                for item in chunk
            ]
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            warnings.append(f"OSV 查詢失敗（{type(exc).__name__}）：{exc}")
            break
        batch = data.get("results") or []
        results.extend(item if isinstance(item, dict) else {} for item in batch)
    return results, warnings


def _fetch_vuln_details(
    vuln_ids: list[str], api_url: str, timeout: int
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """querybatch 只回傳 id/modified，需逐筆抓完整 advisory。"""

    details: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    endpoint = api_url.rstrip("/") + "/v1/vulns/"

    for vuln_id in vuln_ids[:_MAX_DETAIL_FETCHES]:
        request = urllib.request.Request(
            endpoint + urllib.parse.quote(vuln_id, safe=""),
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            warnings.append(f"OSV advisory {vuln_id} 取得失敗（{type(exc).__name__}）：{exc}")
            details[vuln_id] = {"id": vuln_id}
            continue
        details[vuln_id] = data if isinstance(data, dict) else {"id": vuln_id}

    if len(vuln_ids) > _MAX_DETAIL_FETCHES:
        warnings.append(
            f"OSV advisory 數量 {len(vuln_ids)} 超過上限 {_MAX_DETAIL_FETCHES}，"
            f"其餘只保留 id。"
        )
        for vuln_id in vuln_ids[_MAX_DETAIL_FETCHES:]:
            details.setdefault(vuln_id, {"id": vuln_id})
    return details, warnings


def scan_cargo_lock(
    root: Path, *, timeout: int | None = None
) -> tuple[list[Finding], list[str], dict[str, Any]]:
    """掃描 root 下所有 Cargo.lock，回傳 findings、warnings 與統計。"""

    settings = get_settings()
    stats: dict[str, Any] = {
        "enabled": settings.osv_enabled,
        "ecosystem": "crates.io",
        "lockfiles": 0,
        "packages": 0,
        "vulnerable_packages": 0,
        "vulnerabilities": 0,
    }
    if not settings.osv_enabled:
        return [], [], stats

    lockfiles = _iter_lockfiles(root)
    stats["lockfiles"] = len(lockfiles)
    if not lockfiles:
        return [], [], stats

    warnings: list[str] = []
    package_rows: list[dict[str, Any]] = []
    for lockfile in lockfiles:
        try:
            parsed = parse_cargo_lock(lockfile)
        except ValueError as exc:
            warnings.append(f"Cargo.lock 解析失敗：{exc}")
            continue
        relative = str(lockfile.relative_to(root))
        for item in parsed:
            package_rows.append({**item, "file": relative})

    stats["packages"] = len(package_rows)
    if not package_rows:
        return [], [], stats

    if len(package_rows) > settings.osv_max_packages:
        warnings.append(
            f"Cargo.lock 套件數 {len(package_rows)} 超過上限 "
            f"{settings.osv_max_packages}，只查詢前 {settings.osv_max_packages} 個。"
        )
        package_rows = package_rows[: settings.osv_max_packages]
        stats["packages"] = len(package_rows)

    query_rows = [
        {"name": item["name"], "version": item["version"]} for item in package_rows
    ]
    results, query_warnings = _query_osv(
        query_rows,
        settings.osv_api_url,
        timeout or settings.osv_timeout_sec,
    )
    warnings.extend(query_warnings)
    stats["queried"] = len(results)

    vuln_ids: list[str] = []
    for result in results:
        for vuln in result.get("vulns") or []:
            if isinstance(vuln, dict) and vuln.get("id"):
                vuln_id = str(vuln["id"])
                if vuln_id not in vuln_ids:
                    vuln_ids.append(vuln_id)
    details, detail_warnings = _fetch_vuln_details(
        vuln_ids,
        settings.osv_api_url,
        timeout or settings.osv_timeout_sec,
    )
    warnings.extend(detail_warnings)
    stats["advisories"] = len(vuln_ids)

    findings: list[Finding] = []
    seen_ids: dict[tuple[str, str, str], set[str]] = {}
    vulnerable_packages: set[tuple[str, str, str]] = set()
    by_severity: dict[str, int] = {}

    for package, result in zip(package_rows, results):
        package_key = (package["file"], package["name"], package["version"])
        for reference in result.get("vulns") or []:
            if not isinstance(reference, dict):
                continue
            vuln_id = str(reference.get("id") or "OSV-UNKNOWN")
            vuln = details.get(vuln_id) or reference
            aliases = [str(item) for item in vuln.get("aliases") or [] if item]
            identities = {vuln_id, *aliases}
            known = seen_ids.setdefault(package_key, set())
            if identities & known:
                # OSV 會把同一個 advisory 以 GHSA／RUSTSEC／CVE 多個 id 回傳，
                # 依 alias 去重，避免同一問題重複計數。
                continue
            known.update(identities)

            severity = vulnerability_severity(vuln)
            by_severity[severity] = by_severity.get(severity, 0) + 1
            vulnerable_packages.add(package_key)

            summary = str(vuln.get("summary") or vuln.get("details") or "").strip()
            message = f"{package['name']} {package['version']} 存在已知漏洞 {vuln_id}"
            if summary:
                message += f"：{summary[:300]}"
            fixed = _fixed_versions(vuln, package["name"])
            if fixed:
                message += f"（修復版本：{', '.join(fixed[:5])}）"
            if aliases:
                message += f"［{', '.join(aliases[:3])}］"

            findings.append(
                Finding(
                    rule_id=f"osv-{vuln_id}",
                    severity=severity,  # type: ignore[arg-type]
                    message=message,
                    file=package["file"],
                    line=package.get("line"),
                    cwe=_cwe_ids(vuln),
                    engine="osv",
                )
            )

    stats["vulnerable_packages"] = len(vulnerable_packages)
    stats["vulnerabilities"] = len(findings)
    stats["by_severity"] = by_severity
    stats["warnings"] = warnings[:10]
    return findings, warnings, stats
