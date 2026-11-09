"""跨函式 taint 分析使用的內部資料模型。"""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node


@dataclass
class Param:
    name: str
    line: int
    code: str


@dataclass
class Step:
    """資料流的一站；role 只用 source / propagator / sink。"""

    role: str
    file: str
    line: int | None
    code: str | None = None

    def as_propagator(self) -> "Step":
        return Step("propagator", self.file, self.line, self.code)


@dataclass
class Taint:
    """一個被污染的運算式。

    origin 是 ("source",) 或 ("param", index)；steps 是目前為止的路徑。
    """

    origin: tuple
    steps: list[Step]

    def extend(self, step: Step) -> "Taint":
        if self.steps and step.file == self.steps[-1].file and step.line == self.steps[-1].line:
            return self
        return Taint(self.origin, [*self.steps, step])


@dataclass
class Import:
    module: str
    names: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class FunctionInfo:
    key: str
    name: str
    file: str
    language: str
    params: list[Param]
    body: Node
    node: Node
    start_line: int
    # 只有 expression-bodied 函式（C#）會用到：整個 body 就是回傳值。
    expression_body: Node | None = None


@dataclass
class SinkRule:
    kind: str
    cwe: str
    severity: str
    message: str
    patterns: dict[str, list[str]]
    receivers: list[str] = field(default_factory=list)


@dataclass
class SinkHit:
    rule: SinkRule
    steps: list[Step]
    file: str
    line: int
    column: int | None
    code: str


@dataclass
class Summary:
    """函式摘要：哪些參數會流向 sink、哪些參數會流向回傳值。"""

    param_sinks: dict[int, list[SinkHit]] = field(default_factory=dict)
    param_returns: set[int] = field(default_factory=set)
    # 函式直接回傳 source（例如 get_name() -> request.args.get(...)）時的路徑。
    source_return: list[Step] = field(default_factory=list)

    def add_sink(self, index: int, hit: SinkHit) -> None:
        hits = self.param_sinks.setdefault(index, [])
        for position, existing in enumerate(hits):
            if (
                existing.rule.kind == hit.rule.kind
                and existing.file == hit.file
                and existing.line == hit.line
            ):
                if len(hit.steps) < len(existing.steps):
                    hits[position] = hit
                return
        hits.append(hit)

    def signature(self) -> frozenset:
        sinks = frozenset(
            (
                index,
                hit.rule.kind,
                hit.file,
                hit.line,
                tuple((step.file, step.line) for step in hit.steps),
            )
            for index, hits in self.param_sinks.items()
            for hit in hits
        )
        returns = frozenset(self.param_returns)
        return frozenset(
            {
                ("sinks", sinks),
                ("returns", returns),
                ("source_return", tuple((step.file, step.line) for step in self.source_return)),
            }
        )
