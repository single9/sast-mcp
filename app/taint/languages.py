"""Tree-sitter 語言轉接層。

把各語言的 AST 正規化成 analyzer 需要的四種概念：
函式定義、函式呼叫、賦值、回傳。這裡只做語法層的抽取，
taint 語意由 analyzer 負責。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from tree_sitter import Language, Node, Parser

from .model import FunctionInfo, Import, Param


@dataclass
class ParsedFile:
    path: str
    language: str
    source: bytes
    root: Node
    lines: list[str]

    def text(self, node: Node | None) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def line_text(self, row: int) -> str:
        if 0 <= row < len(self.lines):
            return self.lines[row].strip()[:300]
        return ""


def _first_identifier(node: Node) -> Node | None:
    if node.type in {"identifier", "property_identifier", "field_identifier", "type_identifier"}:
        return node
    for child in node.children:
        found = _first_identifier(child)
        if found is not None:
            return found
    return None


def _declarator_identifier(node: Node) -> Node | None:
    """C/C++ 的 declarator 可能包好幾層 pointer/function declarator。"""
    current = node
    while current is not None:
        if current.type in {
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "destructor_name",
        }:
            return current
        child = current.child_by_field_name("declarator")
        if child is None:
            child = next((c for c in current.children if c.is_named), None)
        current = child
    return None


def _last_named_child(node: Node) -> Node | None:
    for child in reversed(node.children):
        if child.is_named:
            return child
    return None


class LanguageAdapter:
    name: str = ""
    extensions: tuple[str, ...] = ()
    call_types: tuple[str, ...] = ()

    def __init__(self, language: Language) -> None:
        self.language = language
        self.parser = Parser(language)

    # -- 基本 ---------------------------------------------------------
    def parse(self, source: bytes) -> Node:
        return self.parser.parse(source).root_node

    def walk(self, node: Node) -> Iterator[Node]:
        yield node
        for child in node.children:
            yield from self.walk(child)

    def unwrap(self, node: Node) -> Node:
        return node

    # -- 函式 ---------------------------------------------------------
    def is_function(self, node: Node) -> bool:
        return False

    def function_name(self, node: Node, pf: ParsedFile) -> str:
        field = node.child_by_field_name("name")
        return pf.text(field)

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        return []

    def function_body(self, node: Node) -> Node | None:
        return node.child_by_field_name("body")

    def expression_body(self, node: Node) -> Node | None:
        return None

    # -- 呼叫 ---------------------------------------------------------
    def is_call(self, node: Node) -> bool:
        return node.type in self.call_types

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        return pf.text(node.child_by_field_name("function"))

    def call_args(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return []
        return [child for child in arguments.children if child.is_named]

    def call_receiver(self, node: Node) -> Node | None:
        """方法呼叫的接收者；用來讓 taint 穿過 .trim()、.clone() 之類的鏈式呼叫。"""

        return None

    # -- 賦值 ---------------------------------------------------------
    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return []
        return [(left, right)]

    # -- 回傳 ---------------------------------------------------------
    def is_return(self, node: Node) -> bool:
        return node.type in {"return_statement", "return_expression"}

    def return_value(self, node: Node) -> Node | None:
        for child in node.children:
            if child.is_named:
                return child
        return None

    # -- import -------------------------------------------------------
    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        return []


class PythonAdapter(LanguageAdapter):
    name = "python"
    extensions = (".py",)
    call_types = ("call",)

    def is_function(self, node: Node) -> bool:
        return node.type in {"function_definition", "lambda"}

    def function_name(self, node: Node, pf: ParsedFile) -> str:
        if node.type == "lambda":
            return f"<lambda@{node.start_point[0] + 1}>"
        return pf.text(node.child_by_field_name("name"))

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named:
                continue
            if child.type in {"identifier", "keyword_identifier"}:
                ident = child
            elif child.type in {
                "default_parameter",
                "typed_default_parameter",
                "typed_parameter",
                "list_splat_pattern",
                "dictionary_splat_pattern",
            }:
                ident = (
                    child.child_by_field_name("name")
                    or child.child_by_field_name("pattern")
                    or _first_identifier(child)
                )
            else:
                ident = _first_identifier(child)
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        return pf.text(node.child_by_field_name("function"))

    def call_receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is not None and function.type == "attribute":
            return function.child_by_field_name("object")
        return None

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type in {"assignment", "augmented_assignment"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        if node.type == "named_expression":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                return [(name, value)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            module = pf.text(module_node)
            names: list[str] = []
            aliases: dict[str, str] = {}
            for child in node.children:
                if not child.is_named or child is module_node:
                    continue
                if child.type == "dotted_name":
                    names.append(pf.text(child))
                elif child.type == "aliased_import":
                    name = pf.text(child.child_by_field_name("name"))
                    alias = pf.text(child.child_by_field_name("alias")) or name
                    names.append(name)
                    aliases[name] = alias
            return [Import(module, names, aliases)] if module else []
        if node.type == "import_statement":
            result: list[Import] = []
            for child in node.children:
                if not child.is_named:
                    continue
                if child.type == "dotted_name":
                    module = pf.text(child)
                    result.append(Import(module, [module.split(".")[-1]]))
                elif child.type == "aliased_import":
                    name = pf.text(child.child_by_field_name("name"))
                    alias = pf.text(child.child_by_field_name("alias")) or name
                    result.append(Import(name, [name.split(".")[-1]], {name.split(".")[-1]: alias}))
            return result
        return []


class JavaScriptAdapter(LanguageAdapter):
    name = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs")
    call_types = ("call_expression", "new_expression")

    def is_function(self, node: Node) -> bool:
        return node.type in {
            "function_declaration",
            "generator_function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        }

    def function_name(self, node: Node, pf: ParsedFile) -> str:
        name = node.child_by_field_name("name")
        if name is not None:
            return pf.text(name)
        parent = node.parent
        if parent is not None:
            if parent.type == "variable_declarator":
                return pf.text(parent.child_by_field_name("name"))
            if parent.type == "assignment_expression":
                return pf.text(parent.child_by_field_name("left"))
            if parent.type in {"pair", "property"}:
                return pf.text(parent.child_by_field_name("key"))
            if parent.type == "export_statement":
                declaration = parent.child_by_field_name("declaration")
                if declaration is not None and declaration is not node:
                    return self.function_name(declaration, pf)
        return f"<anonymous@{node.start_point[0] + 1}>"

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named:
                continue
            if child.type in {"identifier"}:
                ident = child
            elif child.type in {"required_parameter", "optional_parameter"}:
                ident = child.child_by_field_name("pattern") or _first_identifier(child)
            elif child.type == "assignment_pattern":
                ident = child.child_by_field_name("left") or _first_identifier(child)
            elif child.type == "rest_pattern":
                ident = _first_identifier(child)
            else:
                ident = _first_identifier(child)
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def function_body(self, node: Node) -> Node | None:
        return node.child_by_field_name("body")

    def expression_body(self, node: Node) -> Node | None:
        body = node.child_by_field_name("body")
        if body is not None and body.type not in {"statement_block"}:
            return body
        return None

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        if node.type == "new_expression":
            constructor = node.child_by_field_name("constructor")
            return f"new {pf.text(constructor)}".strip()
        return pf.text(node.child_by_field_name("function"))

    def call_receiver(self, node: Node) -> Node | None:
        if node.type == "new_expression":
            return None
        function = node.child_by_field_name("function")
        if function is not None and function.type == "member_expression":
            return function.child_by_field_name("object")
        return None

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type in {"variable_declarator"}:
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                return [(name, value)]
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            module = pf.text(source).strip("'\"")
            if not module:
                return []
            names: list[str] = []
            aliases: dict[str, str] = {}
            for child in self.walk(node):
                if child.type == "import_specifier":
                    name = pf.text(child.child_by_field_name("name"))
                    alias = pf.text(child.child_by_field_name("alias")) or name
                    if name:
                        names.append(name)
                        aliases[name] = alias
                elif child.type == "import_clause":
                    for item in child.children:
                        if item.is_named and item.type == "identifier":
                            default = pf.text(item)
                            names.append(default)
                            aliases[default] = default
            return [Import(module, names, aliases)]
        if node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type == "call_expression":
                callee = pf.text(value.child_by_field_name("function"))
                if callee == "require":
                    args = self.call_args(value)
                    if args:
                        module = pf.text(args[0]).strip("'\"")
                        target = node.child_by_field_name("name")
                        names: list[str] = []
                        aliases: dict[str, str] = {}
                        if target is not None and target.type == "object_pattern":
                            for item in target.children:
                                if item.type == "shorthand_property_identifier_pattern":
                                    name = pf.text(item)
                                    names.append(name)
                                    aliases[name] = name
                                elif item.type == "pair_pattern":
                                    key = pf.text(item.child_by_field_name("key"))
                                    local = pf.text(item.child_by_field_name("value")) or key
                                    if key:
                                        names.append(key)
                                        aliases[key] = local
                        elif target is not None:
                            name = pf.text(target)
                            names.append(name)
                            aliases[name] = name
                        if names:
                            return [Import(module, names, aliases)]
        return []

    def unwrap(self, node: Node) -> Node:
        while node.type in {
            "parenthesized_expression",
            "as_expression",
            "non_null_expression",
            "type_assertion",
            "satisfies_expression",
        }:
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                break
            node = inner
        return node


class TypeScriptAdapter(JavaScriptAdapter):
    name = "typescript"
    extensions = (".ts",)


class TsxAdapter(TypeScriptAdapter):
    extensions = (".tsx",)


class JavaAdapter(LanguageAdapter):
    name = "java"
    extensions = (".java",)
    call_types = ("method_invocation", "object_creation_expression")

    def is_function(self, node: Node) -> bool:
        return node.type in {"method_declaration", "constructor_declaration"}

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named:
                continue
            ident = child.child_by_field_name("name")
            if ident is None:
                ident = _first_identifier(child)
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        if node.type == "object_creation_expression":
            return f"new {pf.text(node.child_by_field_name('type'))}".strip()
        obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name")
        if obj is not None:
            return f"{pf.text(obj)}.{pf.text(name)}"
        return pf.text(name)

    def call_receiver(self, node: Node) -> Node | None:
        if node.type == "object_creation_expression":
            return None
        return node.child_by_field_name("object")

    def call_args(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return []
        return [child for child in arguments.children if child.is_named]

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                return [(name, value)]
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "import_declaration":
            name = _first_identifier(node)
            if name is None:
                return []
            text = pf.text(name)
            return [Import(text, [text.split(".")[-1]])]
        return []

    def unwrap(self, node: Node) -> Node:
        while node.type in {"parenthesized_expression", "cast_expression"}:
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                break
            node = inner
        return node


class CSharpAdapter(LanguageAdapter):
    name = "c_sharp"
    extensions = (".cs",)
    call_types = ("invocation_expression", "object_creation_expression")

    def is_function(self, node: Node) -> bool:
        return node.type in {
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
        }

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named:
                continue
            ident = child.child_by_field_name("name") or _first_identifier(child)
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def function_body(self, node: Node) -> Node | None:
        body = node.child_by_field_name("body")
        if body is not None:
            return body
        return node.child_by_field_name("expression_body")

    def expression_body(self, node: Node) -> Node | None:
        if node.child_by_field_name("body") is not None:
            return None
        return node.child_by_field_name("expression_body")

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        if node.type == "object_creation_expression":
            return f"new {pf.text(node.child_by_field_name('type'))}".strip()
        return pf.text(node.child_by_field_name("function"))

    def call_receiver(self, node: Node) -> Node | None:
        if node.type == "object_creation_expression":
            return None
        function = node.child_by_field_name("function")
        if function is not None and function.type == "member_access_expression":
            return function.child_by_field_name("expression")
        return None

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name is None:
                return []
            value = None
            for child in node.children:
                if child.is_named and child is not name:
                    value = child
            if value is not None:
                return [(name, value)]
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "using_directive":
            name = _first_identifier(node)
            if name is None:
                return []
            text = pf.text(name)
            return [Import(text, [text.split(".")[-1]])]
        return []

    def unwrap(self, node: Node) -> Node:
        while node.type in {
            "argument",
            "parenthesized_expression",
            "cast_expression",
            "as_expression",
        }:
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                break
            node = inner
        return node


class CAdapter(LanguageAdapter):
    name = "c"
    extensions = (".c", ".h")
    call_types = ("call_expression",)

    def is_function(self, node: Node) -> bool:
        return node.type == "function_definition"

    def function_name(self, node: Node, pf: ParsedFile) -> str:
        declarator = node.child_by_field_name("declarator")
        ident = _declarator_identifier(declarator) if declarator is not None else None
        return pf.text(ident)

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            return []
        if declarator.type != "function_declarator":
            declarator = next(
                (c for c in declarator.children if c.type == "function_declarator"), declarator
            )
        parameters = declarator.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named or child.type == "variadic_parameter":
                continue
            decl = child.child_by_field_name("declarator")
            ident = _declarator_identifier(decl) if decl is not None else _first_identifier(child)
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def function_body(self, node: Node) -> Node | None:
        return node.child_by_field_name("body")

    def call_receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is not None and function.type == "field_expression":
            return function.child_by_field_name("argument")
        return None

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type == "init_declarator":
            declarator = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            if declarator is not None and value is not None:
                return [(declarator, value)]
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "preproc_include":
            path = node.child_by_field_name("path")
            text = pf.text(path).strip('<>"')
            return [Import(text, [])] if text else []
        return []

    def unwrap(self, node: Node) -> Node:
        while node.type in {"parenthesized_expression", "cast_expression"}:
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                break
            node = inner
        return node


class CppAdapter(CAdapter):
    name = "cpp"
    extensions = (".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx")
    call_types = ("call_expression", "new_expression")

    def call_name(self, node: Node, pf: ParsedFile) -> str:
        if node.type == "new_expression":
            return f"new {pf.text(node.child_by_field_name('type'))}".strip()
        return pf.text(node.child_by_field_name("function"))

    def function_name(self, node: Node, pf: ParsedFile) -> str:
        declarator = node.child_by_field_name("declarator")
        ident = _declarator_identifier(declarator) if declarator is not None else None
        text = pf.text(ident)
        return text.split("::")[-1]


class RustAdapter(LanguageAdapter):
    name = "rust"
    extensions = (".rs",)
    call_types = ("call_expression",)

    def is_function(self, node: Node) -> bool:
        return node.type == "function_item"

    def function_params(self, node: Node, pf: ParsedFile) -> list[Param]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            return []
        result: list[Param] = []
        for child in parameters.children:
            if not child.is_named or child.type == "self_parameter":
                continue
            pattern = child.child_by_field_name("pattern") or _first_identifier(child)
            ident = _first_identifier(pattern) if pattern is not None else None
            if ident is None:
                continue
            result.append(
                Param(pf.text(ident), ident.start_point[0] + 1, pf.line_text(ident.start_point[0]))
            )
        return result

    def call_receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is not None and function.type == "field_expression":
            return function.child_by_field_name("value")
        return None

    def assignment_pairs(self, node: Node) -> list[tuple[Node, Node]]:
        if node.type == "let_declaration":
            pattern = node.child_by_field_name("pattern")
            value = node.child_by_field_name("value")
            if pattern is not None and value is not None:
                return [(pattern, value)]
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                return [(left, right)]
        return []

    def imports(self, node: Node, pf: ParsedFile) -> list[Import]:
        if node.type == "use_declaration":
            argument = node.child_by_field_name("argument")
            text = pf.text(argument)
            if not text:
                return []
            name = text.split("::")[-1].strip()
            return [Import(text, [name])]
        return []

    def unwrap(self, node: Node) -> Node:
        while node.type in {"parenthesized_expression", "reference_expression"}:
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                break
            node = inner
        return node


_ADAPTERS: list[LanguageAdapter] | None = None


def get_adapters() -> list[LanguageAdapter]:
    """延遲建立 adapter；tree-sitter 未安裝時讓呼叫端處理 ImportError。"""

    global _ADAPTERS
    if _ADAPTERS is not None:
        return _ADAPTERS

    import tree_sitter_c
    import tree_sitter_c_sharp
    import tree_sitter_cpp
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_python
    import tree_sitter_rust
    import tree_sitter_typescript

    adapters: list[LanguageAdapter] = [
        PythonAdapter(Language(tree_sitter_python.language())),
        JavaScriptAdapter(Language(tree_sitter_javascript.language())),
        TypeScriptAdapter(Language(tree_sitter_typescript.language_typescript())),
        TsxAdapter(Language(tree_sitter_typescript.language_tsx())),
        JavaAdapter(Language(tree_sitter_java.language())),
        CSharpAdapter(Language(tree_sitter_c_sharp.language())),
        CAdapter(Language(tree_sitter_c.language())),
        CppAdapter(Language(tree_sitter_cpp.language())),
        RustAdapter(Language(tree_sitter_rust.language())),
    ]
    _ADAPTERS = adapters
    return adapters


def adapter_for_extension(extension: str) -> LanguageAdapter | None:
    for adapter in get_adapters():
        if extension in adapter.extensions:
            return adapter
    return None


def collect_functions(pf: ParsedFile, adapter: LanguageAdapter) -> list[FunctionInfo]:
    result: list[FunctionInfo] = []
    for node in adapter.walk(pf.root):
        if not adapter.is_function(node):
            continue
        body = adapter.function_body(node)
        if body is None:
            continue
        name = adapter.function_name(node, pf)
        params = adapter.function_params(node, pf)
        expression = adapter.expression_body(node)
        result.append(
            FunctionInfo(
                key=f"{pf.path}:{name}:{node.start_point[0] + 1}",
                name=name,
                file=pf.path,
                language=adapter.name,
                params=params,
                body=body,
                node=node,
                start_line=node.start_point[0] + 1,
                expression_body=expression,
            )
        )
    return result
