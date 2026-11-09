"""掃描結果轉 SARIF 2.1.0，方便串接 GitHub Code Scanning 等工具。"""

from __future__ import annotations

from .languages import language_for_path
from .models import Finding, ScanOut

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def scan_to_sarif(scan: ScanOut, findings: list[Finding]) -> dict:
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []

    for finding in findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.message.split("。")[0][:120]},
                    "fullDescription": {"text": finding.message},
                    "defaultConfiguration": {"level": _LEVEL.get(finding.severity, "note")},
                    "properties": {
                        "tags": ["security"],
                        "cwe": finding.cwe,
                        "engine": finding.engine,
                    },
                }
            )

        region: dict = {}
        if finding.line:
            region["startLine"] = finding.line
        if finding.column:
            region["startColumn"] = finding.column
        if finding.end_line:
            region["endLine"] = finding.end_line

        physical: dict = {"artifactLocation": {"uri": finding.file}}
        if region:
            physical["region"] = region

        result: dict = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVEL.get(finding.severity, "note"),
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": physical}],
            "properties": {
                "severity": finding.severity,
                "cwe": finding.cwe,
                "engine": finding.engine,
                "language": language_for_path(finding.file),
                "fingerprint": finding.fingerprint,
                "triageStatus": finding.triage_status,
                "triageNote": finding.triage_note,
                "suppressed": finding.suppressed,
                "regressed": finding.regressed,
            },
        }
        if finding.suppressed:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": finding.triage_note
                    or f"triage: {finding.triage_status or 'suppressed'}",
                }
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sast-service",
                        "informationUri": "https://github.com/",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": scan.status == "completed",
                        "startTimeUtc": scan.started_at,
                        "endTimeUtc": scan.finished_at,
                    }
                ],
                "results": results,
                "properties": {
                    "scanId": scan.id,
                    "engine": scan.engine,
                    "sourceType": scan.source_type,
                    "sourceRef": scan.source_ref,
                    "primaryLanguage": (scan.stats or {}).get("primary_language"),
                    "languages": ((scan.stats or {}).get("languages") or {}).get("languages", []),
                    "languageRisk": ((scan.stats or {}).get("language_risk") or {}).get("languages", []),
                    "dependencies": (scan.stats or {}).get("dependencies"),
                    "supplyChain": (scan.stats or {}).get("supply_chain"),
                    "triage": (scan.stats or {}).get("triage"),
                    "suppressed": (scan.stats or {}).get("suppressed", 0),
                },
            }
        ],
    }
