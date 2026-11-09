"""Summary-based interprocedural taint 分析。

流程：
1. 解析所有檔案，建立函式索引與 import 對應。
2. 對每個函式計算摘要：哪個參數會流向 sink、哪個參數會流向 return。
   摘要會互相依賴，因此用 worklist/fixpoint 迭代到穩定。
3. 再跑一次，從真正的 source（request.args、argv…）出發，
   在呼叫點用被呼叫者的摘要把路徑接到 sink，產生跨檔案 finding。

這是 context-insensitive 的設計：同一個參數只保留最短的一條路徑。
精度不如商業工具，但完全免費、可解釋，且不會把來源與 sink 硬湊在一起。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from ..config import EXCLUDE_DIRS
from .languages import (
    LanguageAdapter,
    ParsedFile,
    adapter_for_extension,
    collect_functions,
)
from .model import FunctionInfo, Import, SinkHit, SinkRule, Step, Summary, Taint
from .rules import RuleSet, normalize_name, split_name

logger = logging.getLogger(__name__)

_MAX_CANDIDATES = 6
_MAX_STEPS = 40


@dataclass
class Repository:
    root: Path
    files: dict[str, ParsedFile] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    by_name: dict[str, list[FunctionInfo]] = field(default_factory=dict)
    by_file: dict[str, list[FunctionInfo]] = field(default_factory=dict)
    # caller file -> local name -> (target file, original function name)
    imports: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)


@dataclass
class AnalyzeContext:
    function: FunctionInfo
    parsed: ParsedFile
    adapter: LanguageAdapter
    mode: str
    summary: Summary
    hits: list[SinkHit]
    env: dict[str, Taint] = field(default_factory=dict)
    seen: set[tuple[str, str, int]] = field(default_factory=set)


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_source_files(root: Path, max_files: int, max_bytes: int):
    count = 0
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for name in sorted(names):
            path = Path(current) / name
            adapter = adapter_for_extension(path.suffix.lower())
            if adapter is None:
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield path, adapter
            count += 1
            if count >= max_files:
                return


def _resolve_python_module(repo: Repository, caller: str, module: str) -> str | None:
    caller_path = Path(caller)
    if module.startswith("."):
        dots = len(module) - len(module.lstrip("."))
        rest = module[dots:]
        base = caller_path.parent
        for _ in range(max(0, dots - 1)):
            base = base.parent
        target = base / rest.replace(".", "/") if rest else base
    else:
        target = Path(module.replace(".", "/"))

    for candidate in (target.with_suffix(".py"), target / "__init__.py"):
        key = candidate.as_posix().lstrip("./")
        if key in repo.files:
            return key
    return None


def _resolve_js_module(repo: Repository, caller: str, module: str) -> str | None:
    if not module.startswith("."):
        return None
    base = Path(os.path.normpath((Path(caller).parent / module).as_posix()))
    candidates = [base]
    for extension in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        candidates.append(base.with_suffix(extension))
        candidates.append(base / f"index{extension}")
    for candidate in candidates:
        key = candidate.as_posix().lstrip("./")
        if key in repo.files:
            return key
    return None


def _resolve_module(repo: Repository, caller: str, module: str, language: str) -> str | None:
    if language == "python":
        return _resolve_python_module(repo, caller, module)
    if language in {"javascript", "typescript"}:
        return _resolve_js_module(repo, caller, module)
    # Java / C# / C / C++ / Rust：用檔名或命名空間的尾段比對。
    tail = module.replace("::", "/").replace(".", "/").split("/")[-1]
    for path in repo.files:
        stem = Path(path).stem
        if stem == tail or stem == f"{tail}Test":
            return path
    return None


def load_repository(
    root: Path, max_files: int = 5000, max_bytes: int = 1_500_000
) -> Repository:
    repo = Repository(root=root)
    for path, adapter in _iter_source_files(root, max_files, max_bytes):
        try:
            source = path.read_bytes()
        except OSError:
            continue
        try:
            tree = adapter.parse(source)
        except Exception as exc:  # noqa: BLE001 - 單一檔案解析失敗不應中斷整個掃描
            logger.debug("taint 解析失敗 %s: %s", path, exc)
            continue
        relative = _rel(root, path)
        parsed = ParsedFile(
            path=relative,
            language=adapter.name,
            source=source,
            root=tree,
            lines=source.decode("utf-8", "replace").splitlines(),
        )
        repo.files[relative] = parsed
        for function in collect_functions(parsed, adapter):
            repo.functions[function.key] = function
            repo.by_name.setdefault(function.name, []).append(function)
            repo.by_file.setdefault(function.file, []).append(function)

    for relative, parsed in repo.files.items():
        adapter = adapter_for_extension(Path(relative).suffix.lower())
        if adapter is None:
            continue
        mapping: dict[str, tuple[str, str]] = {}
        for node in adapter.walk(parsed.root):
            for item in adapter.imports(node, parsed):
                target = _resolve_module(repo, relative, item.module, adapter.name)
                if target is None:
                    continue
                for name in item.names:
                    local = item.aliases.get(name, name.split(".")[-1])
                    mapping[local] = (target, name.split(".")[-1])
        repo.imports[relative] = mapping
    return repo


class Analyzer:
    def __init__(self, repo: Repository, rules: RuleSet, max_iterations: int = 12) -> None:
        self.repo = repo
        self.rules = rules
        self.max_iterations = max_iterations

    # -- 入口 ---------------------------------------------------------
    def run(self) -> tuple[list[SinkHit], dict]:
        summaries: dict[str, Summary] = {key: Summary() for key in self.repo.functions}
        iterations = 0
        for iterations in range(1, self.max_iterations + 1):
            changed = False
            for function in self.repo.functions.values():
                summary = self._analyze(function, summaries, "summary").summary
                if summary.signature() != summaries[function.key].signature():
                    summaries[function.key] = summary
                    changed = True
            if not changed:
                break
        else:
            logger.warning("taint 摘要迭代未收斂，已達上限 %d", self.max_iterations)

        hits: list[SinkHit] = []
        seen: set[tuple[str, str, int, str]] = set()
        for function in self.repo.functions.values():
            for hit in self._analyze(function, summaries, "findings").hits:
                key = (hit.rule.kind, hit.file, hit.line, hit.code)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(hit)

        stats = {
            "functions": len(self.repo.functions),
            "files": len(self.repo.files),
            "iterations": iterations,
            "summaries_with_sinks": sum(1 for s in summaries.values() if s.param_sinks),
        }
        return hits, stats

    # -- 單一函式分析 -------------------------------------------------
    def _analyze(
        self, function: FunctionInfo, summaries: dict[str, Summary], mode: str
    ) -> AnalyzeContext:
        parsed = self.repo.files[function.file]
        adapter = adapter_for_extension(Path(function.file).suffix.lower())
        assert adapter is not None
        context = AnalyzeContext(
            function=function,
            parsed=parsed,
            adapter=adapter,
            mode=mode,
            summary=Summary(),
            hits=[],
        )
        self._summaries = summaries
        if mode == "summary":
            for index, param in enumerate(function.params):
                context.env[param.name] = Taint(
                    ("param", index),
                    [Step("source", function.file, param.line, param.code)],
                )

        if function.expression_body is not None:
            taint = self._eval_expr(function.expression_body, context)
            if taint is not None:
                self._record_return(taint, context)
        else:
            self._visit(function.body, context)
        return context

    def _visit(self, node, context: AnalyzeContext) -> None:
        adapter = context.adapter
        node = adapter.unwrap(node)
        if node is None:
            return
        if adapter.is_function(node) and node is not context.function.node:
            return  # 巢狀函式由 collect_functions 另外處理

        pairs = adapter.assignment_pairs(node)
        if pairs:
            for target, value in pairs:
                taint = self._eval_expr(value, context)
                if taint is not None:
                    name = self._target_name(target, context)
                    if name:
                        context.env[name] = taint
            return

        if adapter.is_call(node):
            self._eval_call(node, context)
            return

        if adapter.is_return(node):
            value = adapter.return_value(node)
            if value is not None:
                taint = self._eval_expr(value, context)
                if taint is not None:
                    self._record_return(taint, context)
            return

        for child in node.children:
            self._visit(child, context)

    def _target_name(self, node, context: AnalyzeContext) -> str | None:
        node = context.adapter.unwrap(node)
        if node.type in {
            "tuple_pattern",
            "list_pattern",
            "array_pattern",
            "object_pattern",
            "tuple",
            "list",
            "array",
            "pattern_list",
            "expression_list",
        }:
            return None
        return normalize_name(context.parsed.text(node))

    # -- 運算式 -------------------------------------------------------
    def _eval_expr(self, node, context: AnalyzeContext) -> Taint | None:
        if node is None:
            return None
        node = context.adapter.unwrap(node)
        if context.adapter.is_call(node):
            return self._eval_call(node, context)

        pairs = context.adapter.assignment_pairs(node)
        if pairs:
            result: Taint | None = None
            for target, value in pairs:
                result = self._eval_expr(value, context)
                if result is not None:
                    name = self._target_name(target, context)
                    if name:
                        context.env[name] = result
            return result

        text = context.parsed.text(node)
        if self.rules.source_for_expr(context.adapter.name, text):
            return self._source_taint(node, context)

        if node.type in {
            "identifier",
            "property_identifier",
            "field_identifier",
            "type_identifier",
            "shorthand_property_identifier",
        }:
            return context.env.get(text)

        result: Taint | None = None
        for child in node.children:
            if not child.is_named:
                continue
            child_taint = self._eval_expr(child, context)
            if child_taint is not None:
                result = child_taint if result is None else _merge(result, child_taint)
        return result

    def _eval_call(self, node, context: AnalyzeContext) -> Taint | None:
        adapter = context.adapter
        name = adapter.call_name(node, context.parsed)
        args = adapter.call_args(node)
        arg_taints = [self._eval_expr(arg, context) for arg in args]
        receiver = adapter.call_receiver(node)
        receiver_taint = self._eval_expr(receiver, context) if receiver is not None else None

        if self.rules.sanitizer_for_call(adapter.name, name):
            return None

        if self.rules.source_for_call(adapter.name, name):
            return self._source_taint(node, context)

        rule = self.rules.sink_for_call(adapter.name, name)

        propagated: Taint | None = None
        target = self.rules.propagator_target(adapter.name, name)
        if target is not None and 0 <= target < len(args):
            propagated = next(
                (
                    item
                    for index, item in enumerate(arg_taints)
                    if index != target and item is not None
                ),
                None,
            )
            if propagated is not None:
                destination = self._target_name(args[target], context)
                if destination:
                    context.env[destination] = propagated

        if rule is not None:
            taint = propagated or next(
                (item for item in [*arg_taints, receiver_taint] if item is not None), None
            )
            if taint is not None:
                self._record_sink(rule, taint, node, context)
            return propagated

        result: Taint | None = None
        for callee in self._resolve_callee(context.function, name):
            summary = self._summaries.get(callee.key)
            if summary is None:
                continue
            if summary.source_return:
                callee_steps = [step.as_propagator() for step in summary.source_return]
                callee_steps[0] = summary.source_return[0]
                candidate = Taint(("source",), callee_steps)
                if result is None or len(candidate.steps) < len(result.steps):
                    result = candidate
            for index, taint in enumerate(arg_taints):
                if taint is None:
                    continue
                for hit in summary.param_sinks.get(index, []):
                    self._record_composed(hit, taint, node, context)
                if index in summary.param_returns and result is None:
                    result = taint

        if result is None:
            for taint in [*arg_taints, receiver_taint]:
                if taint is not None:
                    result = taint
                    break
        if result is not None:
            line = node.start_point[0] + 1
            result = result.extend(
                Step("propagator", context.function.file, line, context.parsed.line_text(line - 1))
            )
        return result

    def _source_taint(self, node, context: AnalyzeContext) -> Taint:
        line = node.start_point[0] + 1
        return Taint(
            ("source",),
            [Step("source", context.function.file, line, context.parsed.line_text(line - 1))],
        )

    # -- 記錄 ---------------------------------------------------------
    def _record_sink(self, rule: SinkRule, taint: Taint, node, context: AnalyzeContext) -> None:
        line = node.start_point[0] + 1
        step = Step("sink", context.function.file, line, context.parsed.line_text(line - 1))
        steps = [*taint.steps]
        while (
            len(steps) >= 2
            and steps[-1].role == "propagator"
            and steps[-1].file == step.file
            and steps[-1].line == step.line
        ):
            steps.pop()
        steps.append(step)
        self._record_hit(rule, steps, taint.origin, context)

    def _record_composed(self, hit: SinkHit, taint: Taint, node, context: AnalyzeContext) -> None:
        line = node.start_point[0] + 1
        call_step = Step(
            "propagator", context.function.file, line, context.parsed.line_text(line - 1)
        )
        callee_steps = [step.as_propagator() for step in hit.steps[:-1]]
        if hit.steps:
            callee_steps.append(hit.steps[-1])
        prefix = [*taint.steps]
        if not (
            prefix
            and prefix[-1].file == call_step.file
            and prefix[-1].line == call_step.line
        ):
            prefix.append(call_step)
        steps = [*prefix, *callee_steps]
        self._record_hit(hit.rule, steps, taint.origin, context)

    def _record_hit(
        self, rule: SinkRule, steps: list[Step], origin: tuple, context: AnalyzeContext
    ) -> None:
        if not steps or steps[-1].role != "sink":
            return
        sink = steps[-1]
        if sink.line is None:
            return
        # 避免同一條路徑被反覆疊加（遞迴或 fixpoint）。
        dedupe = (rule.kind, sink.file, sink.line)
        if context.mode == "findings":
            key = (*dedupe, sink.code or "")
            if key in context.seen:
                return
            context.seen.add(key)

        trimmed = steps
        if len(steps) > _MAX_STEPS:
            trimmed = [steps[0], *steps[-(_MAX_STEPS - 1) :]]

        hit = SinkHit(
            rule=rule,
            steps=trimmed,
            file=sink.file,
            line=sink.line,
            column=None,
            code=sink.code or "",
        )
        if context.mode == "summary":
            # 只保留「參數 → sink」；source 起源的路徑留給 findings 階段。
            if origin[0] == "param":
                context.summary.add_sink(origin[1], hit)
            return
        if origin[0] == "source":
            context.hits.append(hit)

    def _record_return(self, taint: Taint, context: AnalyzeContext) -> None:
        if context.mode != "summary":
            return
        if taint.origin[0] == "param":
            context.summary.param_returns.add(taint.origin[1])
        elif taint.origin[0] == "source":
            current = context.summary.source_return
            if not current or len(taint.steps) < len(current):
                context.summary.source_return = list(taint.steps)

    # -- 呼叫解析 -----------------------------------------------------
    def _resolve_callee(self, caller: FunctionInfo, call_name: str) -> list[FunctionInfo]:
        _full, _receiver, tail = split_name(call_name)
        if not tail:
            return []

        candidates: list[FunctionInfo] = []
        for function in self.repo.by_file.get(caller.file, []):
            if function.name == tail and function.key != caller.key:
                candidates.append(function)

        imported = self.repo.imports.get(caller.file, {}).get(tail)
        if imported is not None:
            target_file, original = imported
            for function in self.repo.by_file.get(target_file, []):
                if function.name in {original, tail}:
                    candidates.append(function)

        if not candidates:
            global_matches = [
                function
                for function in self.repo.by_name.get(tail, [])
                if function.key != caller.key
            ]
            same_language = [
                function for function in global_matches if function.language == caller.language
            ]
            if same_language:
                global_matches = same_language
            if len(global_matches) > 1:
                same_dir = [
                    function
                    for function in global_matches
                    if Path(function.file).parent == Path(caller.file).parent
                ]
                if same_dir:
                    global_matches = same_dir
            if len(global_matches) == 1:
                candidates = global_matches

        unique: dict[str, FunctionInfo] = {}
        for function in candidates[:_MAX_CANDIDATES]:
            unique[function.key] = function
        return list(unique.values())

    _summaries: dict[str, Summary]


def _merge(first: Taint, second: Taint) -> Taint:
    return first if len(first.steps) <= len(second.steps) else second


def analyze_repository(
    root: Path, rules: RuleSet, max_files: int = 5000
) -> tuple[list[SinkHit], dict]:
    repo = load_repository(root, max_files=max_files)
    analyzer = Analyzer(repo, rules)
    return analyzer.run()
