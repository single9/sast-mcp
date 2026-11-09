"""語言偵測與依語言風險彙總的測試。"""

from __future__ import annotations

from pathlib import Path

from app.languages import aggregate_language_risk, detect_languages, language_for_path


def test_language_for_path_recognizes_extensions_and_special_files():
    assert language_for_path("src/app.py") == "python"
    assert language_for_path("src/app.tsx") == "typescript"
    assert language_for_path("src/main.rs") == "rust"
    assert language_for_path("src/Program.cs") == "csharp"
    assert language_for_path("src/main.cpp") == "cpp"
    assert language_for_path("Dockerfile") == "dockerfile"
    assert language_for_path("CMakeLists.txt") == "cmake"
    assert language_for_path("Gemfile") == "ruby"
    assert language_for_path("Cargo.lock") == "toml"
    assert language_for_path("Cargo.toml") == "toml"
    assert language_for_path("README.unknown") is None


def test_detect_languages_counts_files_lines_and_excludes_dependencies(tmp_path: Path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / ".git").mkdir()

    (root / "src" / "app.py").write_text("print(1)\nprint(2)\nprint(3)\n", encoding="utf-8")
    (root / "src" / "lib.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "web.ts").write_text("const a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n\nhello\n", encoding="utf-8")
    (root / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (root / "image.png").write_bytes(b"\x89PNG\r\n")
    (root / "link.py").symlink_to(root / "src" / "app.py")

    stats = detect_languages(root)
    by_id = {item["id"]: item for item in stats["languages"]}

    assert stats["primary_language"] == "typescript"
    assert stats["primary_language_name"] == "TypeScript"
    assert stats["detected_languages"] == 4
    assert stats["total_files"] == 4
    assert stats["percent_basis"] == "lines"

    assert by_id["python"]["files"] == 1
    assert by_id["python"]["lines"] == 3
    assert by_id["rust"]["lines"] == 1
    assert by_id["typescript"]["lines"] == 4
    assert by_id["markdown"]["category"] == "markup"
    assert "javascript" not in by_id
    assert by_id["typescript"]["percent"] > by_id["python"]["percent"]


def test_detect_languages_counts_last_line_without_newline(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.go").write_text("package main", encoding="utf-8")

    stats = detect_languages(root)
    go = next(item for item in stats["languages"] if item["id"] == "go")
    assert go["lines"] == 1


def test_aggregate_language_risk_groups_and_sorts_by_risk():
    languages = {
        "primary_language": "python",
        "languages": [
            {
                "id": "python",
                "name": "Python",
                "category": "code",
                "category_name": "程式碼",
                "files": 2,
                "lines": 10,
                "bytes": 100,
                "percent": 50.0,
            },
            {
                "id": "javascript",
                "name": "JavaScript",
                "category": "code",
                "category_name": "程式碼",
                "files": 1,
                "lines": 5,
                "bytes": 50,
                "percent": 25.0,
            },
            {
                "id": "rust",
                "name": "Rust",
                "category": "code",
                "category_name": "程式碼",
                "files": 1,
                "lines": 5,
                "bytes": 50,
                "percent": 25.0,
            },
        ],
    }
    findings = [
        {"rule_id": "py-high", "severity": "high", "message": "high", "file": "src/a.py"},
        {"rule_id": "py-low", "severity": "low", "message": "low", "file": "src/b.py"},
        {"rule_id": "js-critical", "severity": "critical", "message": "critical", "file": "web/a.js"},
        {"rule_id": "other-medium", "severity": "medium", "message": "other", "file": "notes.txt"},
    ]

    risk = aggregate_language_risk(findings, languages, top_rules=2)
    by_id = {item["id"]: item for item in risk["languages"]}

    assert risk["primary_language"] == "python"
    assert risk["total_findings"] == 4
    assert [item["id"] for item in risk["languages"][:2]] == ["javascript", "python"]

    assert by_id["javascript"]["findings"] == 1
    assert by_id["javascript"]["risk_level"] == "critical"
    assert by_id["javascript"]["risk_score"] == 10
    assert by_id["javascript"]["severity_counts"]["critical"] == 1

    assert by_id["python"]["findings"] == 2
    assert by_id["python"]["risk_level"] == "high"
    assert by_id["python"]["risk_score"] == 6
    assert by_id["python"]["top_rules"][0]["rule_id"] == "py-high"

    assert by_id["rust"]["findings"] == 0
    assert by_id["rust"]["risk_level"] == "none"

    assert by_id["other"]["findings"] == 1
    assert by_id["other"]["risk_level"] == "medium"
    assert risk["risk_levels"]["critical"] == 1


def test_aggregate_language_risk_without_project_stats_still_groups_findings():
    findings = [{"rule_id": "r1", "severity": "high", "message": "m", "file": "app.rb"}]
    risk = aggregate_language_risk(findings)
    ruby = next(item for item in risk["languages"] if item["id"] == "ruby")
    assert ruby["files"] == 0
    assert ruby["findings"] == 1
    assert risk["primary_language"] == "ruby"
