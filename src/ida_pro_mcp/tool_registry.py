"""AST-based tool registry for IDA Pro MCP.

Parses ``mcp-plugin.py`` to extract ``@jsonrpc``-decorated functions and
``TypedDict`` classes, transforming them into MCP tool definitions that
call ``make_jsonrpc_request`` with multi-instance ``instance_id`` support.

Extracted from server.py to improve modularity and testability.

Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
"""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass, field


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class ParseResult:
    """Result of parsing the IDA plugin file."""

    types: dict[str, ast.ClassDef] = field(default_factory=dict)
    functions: dict[str, ast.FunctionDef] = field(default_factory=dict)
    descriptions: dict[str, str] = field(default_factory=dict)
    unsafe: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# AST Visitor
# ------------------------------------------------------------------

class MCPVisitor(ast.NodeVisitor):
    """Extracts ``@jsonrpc``-decorated functions and ``TypedDict`` classes.

    Transforms each function to call ``make_jsonrpc_request()`` with an
    injected ``instance_id`` optional parameter for multi-instance routing.
    """

    def __init__(self) -> None:
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}
        self.unsafe: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    self._process_jsonrpc_function(node)
                elif decorator.id == "unsafe":
                    self.unsafe.append(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "TypedDict":
                self.types[node.name] = node

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process_jsonrpc_function(self, node: ast.FunctionDef) -> None:
        """Transform a @jsonrpc function into an MCP tool definition."""
        # Process argument annotations
        for i, arg in enumerate(node.args.args):
            arg_name = arg.arg
            arg_type = arg.annotation
            if arg_type is None:
                raise Exception(
                    f"Missing argument type for {node.name}.{arg_name}"
                )
            if isinstance(arg_type, ast.Subscript):
                if not isinstance(arg_type.value, ast.Name):
                    raise ValueError(
                        f"Expected ast.Name for Subscript value in "
                        f"{node.name}.{arg_name}, got {type(arg_type.value)}"
                    )
                if arg_type.value.id != "Annotated":
                    raise ValueError(
                        f"Expected 'Annotated' subscript in "
                        f"{node.name}.{arg_name}, got '{arg_type.value.id}'"
                    )
                if not isinstance(arg_type.slice, ast.Tuple):
                    raise ValueError(
                        f"Expected Tuple slice for Annotated in "
                        f"{node.name}.{arg_name}, got {type(arg_type.slice)}"
                    )
                if len(arg_type.slice.elts) != 2:
                    raise ValueError(
                        f"Expected 2 elements in Annotated slice for "
                        f"{node.name}.{arg_name}, got {len(arg_type.slice.elts)}"
                    )
                annot_type = arg_type.slice.elts[0]
                annot_description = arg_type.slice.elts[1]
                if not isinstance(annot_description, ast.Constant):
                    raise ValueError(
                        f"Expected Constant for annotation description in "
                        f"{node.name}.{arg_name}, got {type(annot_description)}"
                    )
                node.args.args[i].annotation = ast.Subscript(
                    value=ast.Name(id="Annotated", ctx=ast.Load()),
                    slice=ast.Tuple(
                        elts=[
                            annot_type,
                            ast.Call(
                                func=ast.Name(id="Field", ctx=ast.Load()),
                                args=[],
                                keywords=[
                                    ast.keyword(
                                        arg="description",
                                        value=annot_description,
                                    )
                                ],
                            ),
                        ],
                        ctx=ast.Load(),
                    ),
                    ctx=ast.Load(),
                )
            elif isinstance(arg_type, ast.Name):
                pass
            else:
                raise Exception(
                    f"Unexpected type annotation for "
                    f"{node.name}.{arg_name} -> {type(arg_type)}"
                )

        # Extract docstring
        body_comment = node.body[0]
        if isinstance(body_comment, ast.Expr) and isinstance(
            body_comment.value, ast.Constant
        ):
            new_body: list[ast.stmt] = [body_comment]
            self.descriptions[node.name] = body_comment.value.value
        else:
            new_body = []

        # Build call: make_jsonrpc_request("method_name", arg1, arg2, ..., instance_id=instance_id)
        call_args: list[ast.expr] = [ast.Constant(value=node.name)]
        for arg in node.args.args:
            call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
        call_keywords = [
            ast.keyword(
                arg="instance_id",
                value=ast.Name(id="instance_id", ctx=ast.Load()),
            )
        ]
        new_body.append(
            ast.Return(
                value=ast.Call(
                    func=ast.Name(id="make_jsonrpc_request", ctx=ast.Load()),
                    args=call_args,
                    keywords=call_keywords,
                )
            )
        )

        # Inject instance_id as optional parameter with Annotated[Optional[str], Field(...)]
        instance_id_arg = ast.arg(
            arg="instance_id",
            annotation=ast.Subscript(
                value=ast.Name(id="Annotated", ctx=ast.Load()),
                slice=ast.Tuple(
                    elts=[
                        ast.Subscript(
                            value=ast.Name(id="Optional", ctx=ast.Load()),
                            slice=ast.Name(id="str", ctx=ast.Load()),
                            ctx=ast.Load(),
                        ),
                        ast.Call(
                            func=ast.Name(id="Field", ctx=ast.Load()),
                            args=[],
                            keywords=[
                                ast.keyword(
                                    arg="description",
                                    value=ast.Constant(
                                        value="Target IDA instance ID. "
                                        "Use list_instances() to see available instances. "
                                        "Omit for single-instance auto-routing."
                                    ),
                                ),
                                ast.keyword(
                                    arg="default",
                                    value=ast.Constant(value=None),
                                ),
                            ],
                        ),
                    ],
                    ctx=ast.Load(),
                ),
                ctx=ast.Load(),
            ),
        )
        new_args = ast.arguments(
            posonlyargs=node.args.posonlyargs,
            args=node.args.args + [instance_id_arg],
            vararg=node.args.vararg,
            kwonlyargs=node.args.kwonlyargs,
            kw_defaults=node.args.kw_defaults,
            kwarg=node.args.kwarg,
            defaults=node.args.defaults + [ast.Constant(value=None)],
        )

        # Build decorator: @mcp.tool()
        decorator_list = [
            ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="mcp", ctx=ast.Load()),
                    attr="tool",
                    ctx=ast.Load(),
                ),
                args=[],
                keywords=[],
            )
        ]

        node_nobody = ast.FunctionDef(
            node.name,
            new_args,
            new_body,
            decorator_list,
            node.returns,
            node.type_comment,
            lineno=node.lineno,
            col_offset=node.col_offset,
        )
        if node.name in self.functions:
            raise ValueError(f"Duplicate @jsonrpc function: {node.name}")
        self.functions[node.name] = node_nobody


# ------------------------------------------------------------------
# High-level API
# ------------------------------------------------------------------

def parse_plugin_file(plugin_path: str) -> ParseResult:
    """Parse the IDA plugin file and extract tool definitions.

    Args:
        plugin_path: Absolute path to ``mcp-plugin.py``.

    Returns:
        ParseResult with types, functions, descriptions, and unsafe lists.

    Raises:
        RuntimeError: If the plugin file is not found.
    """
    if not os.path.exists(plugin_path):
        raise RuntimeError(
            f"IDA plugin not found at {plugin_path} (did you move it?)"
        )

    with open(plugin_path, "r", encoding="utf-8") as f:
        source = f.read()

    module = ast.parse(source, plugin_path)
    visitor = MCPVisitor()
    visitor.visit(module)

    return ParseResult(
        types=visitor.types,
        functions=visitor.functions,
        descriptions=visitor.descriptions,
        unsafe=visitor.unsafe,
    )


def generate_code(result: ParseResult) -> str:
    """Generate the server_generated.py source code from parsed results.

    Args:
        result: Output from ``parse_plugin_file()``.

    Returns:
        Complete Python source code string.
    """
    code = (
        "# NOTE: This file has been automatically generated, do not modify!\n"
        "# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)\n"
        "import sys\n"
        "if sys.version_info >= (3, 12):\n"
        "    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired\n"
        "else:\n"
        "    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired\n"
        "from pydantic import Field\n"
        "\n"
        'T = TypeVar("T")\n'
        "\n"
    )

    for type_node in result.types.values():
        code += ast.unparse(type_node)
        code += "\n\n"

    for func_node in result.functions.values():
        code += ast.unparse(func_node)
        code += "\n\n"

    return code


def write_generated_file(code: str, output_path: str) -> bool:
    """Write generated code to disk if it differs from existing content.

    Args:
        code: Generated Python source code.
        output_path: Path to write to.

    Returns:
        True if the file was updated, False if unchanged.
    """
    try:
        if os.path.exists(output_path):
            with open(output_path, "rb") as f:
                existing_bytes = f.read()
        else:
            existing_bytes = b""

        code_bytes = code.encode("utf-8").replace(b"\r", b"")
        if code_bytes != existing_bytes:
            with open(output_path, "wb") as f:
                f.write(code_bytes)
            return True
        return False
    except Exception:
        print(
            f"Failed to generate code: {output_path}",
            file=sys.stderr,
            flush=True,
        )
        return False


def generate_tool_schemas(result: ParseResult) -> list[dict]:
    """Generate JSON tool schema list from parsed results.

    Produces a list of tool definition dicts suitable for static
    schema export (e.g., ``ida_tool_schemas.json``).

    Args:
        result: Output from ``parse_plugin_file()``.

    Returns:
        List of ``{name, description, parameters}`` dicts.
    """
    schemas: list[dict] = []
    for name, func_node in result.functions.items():
        schema: dict = {
            "name": name,
            "description": result.descriptions.get(name, ""),
        }
        params = []
        for arg in func_node.args.args:
            param: dict = {"name": arg.arg}
            if arg.annotation:
                try:
                    param["type"] = ast.unparse(arg.annotation)
                except Exception:
                    param["type"] = "unknown"
            params.append(param)
        schema["parameters"] = params
        schema["unsafe"] = name in result.unsafe
        schemas.append(schema)
    return schemas
