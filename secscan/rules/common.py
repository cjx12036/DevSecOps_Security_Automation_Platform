from __future__ import annotations

import ast


def get_snippet(lines: list[str], start: int, end: int) -> str:
    start_idx = max(start - 1, 0)
    end_idx = max(end, start)
    return "\n".join(lines[start_idx:end_idx]).strip()[:300]


def get_attr_chain(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_attr_chain(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def node_contains_user_input(node: ast.AST) -> bool:
    user_markers = {"request.args", "request.form", "request.values", "request.json", "input"}
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = get_attr_chain(n.func)
            if fn == "input":
                return True
            if fn.endswith(".get") and isinstance(n.func, ast.Attribute):
                owner = get_attr_chain(n.func.value)
                if owner in {"request.args", "request.form", "request.values", "request.json"}:
                    return True
        elif isinstance(n, ast.Attribute):
            full = get_attr_chain(n)
            if full in user_markers:
                return True
    return False


def is_string_build(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False
