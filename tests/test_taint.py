"""跨函式 taint 引擎的迴歸測試。"""

from __future__ import annotations

from pathlib import Path

from app.models import Finding
from app.taint.analyzer import analyze_repository
from app.taint.rules import load_rules
from app.taint.runner import scan_taint


def _hits(root: Path):
    return analyze_repository(root, load_rules())


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def test_python_cross_file_flow(tmp_path):
    _write(
        tmp_path,
        "app/view.py",
        """\
from .service import run_command


def handler(request):
    name = request.args.get("name")
    return run_command(name)
""",
    )
    _write(
        tmp_path,
        "app/service.py",
        """\
import os


def run_command(name):
    cmd = "echo " + name
    os.system(cmd)
""",
    )

    hits, stats = _hits(tmp_path)

    assert stats["functions"] == 2
    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1
    hit = command[0]
    assert hit.file == "app/service.py"
    assert [step.role for step in hit.steps] == ["source", "propagator", "propagator", "sink"]
    assert {step.file for step in hit.steps} == {"app/view.py", "app/service.py"}
    assert hit.steps[0].code == 'name = request.args.get("name")'


def test_javascript_cross_file_flow_with_destructured_require(tmp_path):
    _write(
        tmp_path,
        "js/view.js",
        """\
const { runCommand } = require("./service");

function handler(req) {
  const name = req.query.name;
  runCommand(name);
}
""",
    )
    _write(
        tmp_path,
        "js/service.js",
        """\
const cp = require("child_process");

function runCommand(name) {
  const cmd = "echo " + name;
  cp.exec(cmd);
}
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1
    assert command[0].file == "js/service.js"
    assert command[0].steps[0].file == "js/view.js"


def test_java_cross_file_flow(tmp_path):
    _write(
        tmp_path,
        "src/View.java",
        """\
class View {
  void handler(HttpServletRequest req) {
    Service.run(req.getParameter("name"));
  }
}
""",
    )
    _write(
        tmp_path,
        "src/Service.java",
        """\
class Service {
  static void run(String name) {
    String cmd = "echo " + name;
    Runtime.getRuntime().exec(cmd);
  }
}
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1
    assert command[0].file == "src/Service.java"
    assert command[0].steps[0].file == "src/View.java"


def test_sanitizer_blocks_flow(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """\
import os
from flask import request


def handler():
    os.system(int(request.args.get("n")))
""",
    )

    hits, _ = _hits(tmp_path)

    assert not [hit for hit in hits if hit.rule.kind == "command-injection"]


def test_return_value_propagation(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """\
import os
from flask import request


def get_name():
    return request.args.get("name")


def handler():
    os.system(get_name())
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1
    roles = [step.role for step in command[0].steps]
    assert roles[0] == "source"
    assert roles[-1] == "sink"


def test_csharp_source_and_sink(tmp_path):
    _write(
        tmp_path,
        "Program.cs",
        """\
using System.Diagnostics;

class A {
  void Run(string name) {
    string cmd = "echo " + name;
    Process.Start(cmd);
  }

  void Handler(HttpRequest req) {
    Run(req.Query["x"]);
  }
}
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1
    assert command[0].file == "Program.cs"


def test_c_printf_to_system_propagation(tmp_path):
    _write(
        tmp_path,
        "main.c",
        """\
#include <stdio.h>
#include <stdlib.h>

void run(char *name) {
  char cmd[256];
  sprintf(cmd, "echo %s", name);
  system(cmd);
}

int main(int argc, char **argv) {
  run(argv[1]);
  return 0;
}
""",
    )

    hits, _ = _hits(tmp_path)

    kinds = {hit.rule.kind for hit in hits}
    assert "format-string" in kinds
    assert "command-injection" in kinds


def test_cpp_cross_function_flow(tmp_path):
    _write(
        tmp_path,
        "main.cpp",
        """\
#include <string>
#include <cstdlib>

void run(std::string name) {
  std::string cmd = "echo " + name;
  system(cmd.c_str());
}

int main(int argc, char **argv) {
  run(argv[1]);
  return 0;
}
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1


def test_rust_cross_function_flow(tmp_path):
    _write(
        tmp_path,
        "main.rs",
        """\
use std::process::Command;

fn run(name: String) {
    let cmd = format!("echo {}", name);
    Command::new("sh").arg("-c").arg(cmd).status();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    run(args[1].clone());
}
""",
    )

    hits, _ = _hits(tmp_path)

    command = [hit for hit in hits if hit.rule.kind == "command-injection"]
    assert len(command) == 1


def test_tsx_files_are_parsed(tmp_path):
    _write(
        tmp_path,
        "component.tsx",
        """\
export function handler(req: any) {
  const name = req.query.name;
  eval(name);
}
""",
    )

    hits, _ = _hits(tmp_path)

    assert [hit for hit in hits if hit.rule.kind == "code-injection"]


def test_runner_merges_into_existing_finding(tmp_path):
    _write(
        tmp_path,
        "app/view.py",
        """\
from .service import run_command


def handler(request):
    name = request.args.get("name")
    return run_command(name)
""",
    )
    _write(
        tmp_path,
        "app/service.py",
        """\
import os


def run_command(name):
    cmd = "echo " + name
    os.system(cmd)
""",
    )

    existing = Finding(
        rule_id="python.lang.security.audit.dangerous-system-call",
        severity="critical",
        message="dangerous system call",
        file="app/service.py",
        line=6,
        cwe=["CWE-78"],
        engine="semgrep",
    )

    new_findings, warnings, stats = scan_taint(tmp_path, [existing])

    assert warnings == []
    assert stats["enabled"] is True
    assert stats["merged"] == 1
    assert not [finding for finding in new_findings if finding.rule_id == "taint-command-injection"]
    assert len(existing.dataflow) == 4
    assert {step.file for step in existing.dataflow} == {"app/view.py", "app/service.py"}


def test_runner_reports_stats_and_is_graceful(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """\
import os
from flask import request


def handler():
    os.system(request.args.get("cmd"))
""",
    )

    new_findings, warnings, stats = scan_taint(tmp_path, [])

    assert warnings == []
    assert stats["enabled"] is True
    assert len(new_findings) >= 1
    assert stats["findings"] == len(new_findings)
    assert stats["by_kind"].get("taint-command-injection") == 1
