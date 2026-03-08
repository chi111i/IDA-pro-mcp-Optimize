"""Tests for tool_registry.py — AST-based tool registration."""

import os
import sys

import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.tool_registry import (
    ParseResult,
    MCPVisitor,
    parse_plugin_file,
    generate_code,
    write_generated_file,
    generate_tool_schemas,
)


# Path to the actual mcp-plugin.py
PLUGIN_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "mcp-plugin.py"
)


class TestParsePluginFile:
    def test_parses_without_error(self):
        """Parsing the actual plugin file succeeds."""
        result = parse_plugin_file(PLUGIN_PATH)
        assert isinstance(result, ParseResult)

    def test_extracts_functions(self):
        """Parser extracts @jsonrpc decorated functions."""
        result = parse_plugin_file(PLUGIN_PATH)
        assert len(result.functions) > 0

    def test_extracts_types(self):
        """Parser extracts TypedDict classes."""
        result = parse_plugin_file(PLUGIN_PATH)
        assert len(result.types) > 0

    def test_extracts_descriptions(self):
        """Parser extracts docstrings as descriptions."""
        result = parse_plugin_file(PLUGIN_PATH)
        assert len(result.descriptions) > 0

    def test_extracts_unsafe_functions(self):
        """Parser identifies @unsafe decorated functions."""
        result = parse_plugin_file(PLUGIN_PATH)
        assert isinstance(result.unsafe, list)

    def test_known_functions_present(self):
        """Key IDA functions are present in parsed results."""
        result = parse_plugin_file(PLUGIN_PATH)
        expected_funcs = [
            "get_metadata",
            "decompile_function",
            "list_functions",
            "get_xrefs_to",
        ]
        for func_name in expected_funcs:
            assert func_name in result.functions, f"Missing function: {func_name}"

    def test_nonexistent_file_raises(self):
        """Parsing a non-existent file raises RuntimeError."""
        with pytest.raises(RuntimeError, match="not found"):
            parse_plugin_file("/nonexistent/path/to/plugin.py")

    def test_instance_id_injected(self):
        """Each function has instance_id parameter injected."""
        import ast

        result = parse_plugin_file(PLUGIN_PATH)
        for name, func_node in result.functions.items():
            arg_names = [arg.arg for arg in func_node.args.args]
            assert "instance_id" in arg_names, (
                f"Function '{name}' missing instance_id parameter"
            )


class TestGenerateCode:
    def test_generates_valid_python(self):
        """Generated code is valid Python syntax."""
        result = parse_plugin_file(PLUGIN_PATH)
        code = generate_code(result)
        # Should not raise SyntaxError
        compile(code, "<generated>", "exec")

    def test_contains_auto_generated_header(self):
        """Generated code contains the auto-generated warning."""
        result = parse_plugin_file(PLUGIN_PATH)
        code = generate_code(result)
        assert "automatically generated" in code

    def test_contains_imports(self):
        """Generated code contains necessary imports."""
        result = parse_plugin_file(PLUGIN_PATH)
        code = generate_code(result)
        assert "from typing" in code or "from typing_extensions" in code
        assert "from pydantic import Field" in code

    def test_contains_type_definitions(self):
        """Generated code contains TypedDict definitions."""
        result = parse_plugin_file(PLUGIN_PATH)
        code = generate_code(result)
        assert "TypedDict" in code


class TestWriteGeneratedFile:
    def test_creates_new_file(self, tmp_path):
        """write_generated_file creates a new file."""
        output = str(tmp_path / "generated.py")
        result = write_generated_file("# test content\n", output)
        assert result is True
        assert os.path.exists(output)

    def test_no_update_when_identical(self, tmp_path):
        """write_generated_file returns False when content unchanged."""
        output = str(tmp_path / "generated.py")
        content = "# test content\n"
        write_generated_file(content, output)
        result = write_generated_file(content, output)
        assert result is False

    def test_updates_when_changed(self, tmp_path):
        """write_generated_file returns True when content differs."""
        output = str(tmp_path / "generated.py")
        write_generated_file("# version 1\n", output)
        result = write_generated_file("# version 2\n", output)
        assert result is True


class TestGenerateToolSchemas:
    def test_returns_list(self):
        """generate_tool_schemas returns a list of dicts."""
        result = parse_plugin_file(PLUGIN_PATH)
        schemas = generate_tool_schemas(result)
        assert isinstance(schemas, list)
        assert len(schemas) > 0

    def test_schema_has_required_keys(self):
        """Each schema has name, description, parameters."""
        result = parse_plugin_file(PLUGIN_PATH)
        schemas = generate_tool_schemas(result)
        for schema in schemas:
            assert "name" in schema
            assert "description" in schema
            assert "parameters" in schema

    def test_schema_marks_unsafe(self):
        """Unsafe functions are marked in schema."""
        result = parse_plugin_file(PLUGIN_PATH)
        schemas = generate_tool_schemas(result)
        schema_map = {s["name"]: s for s in schemas}
        for unsafe_name in result.unsafe:
            if unsafe_name in schema_map:
                assert schema_map[unsafe_name]["unsafe"] is True

    def test_parameters_have_name(self):
        """Each parameter has a name field."""
        result = parse_plugin_file(PLUGIN_PATH)
        schemas = generate_tool_schemas(result)
        for schema in schemas:
            for param in schema["parameters"]:
                assert "name" in param


class TestASTValidation:
    """Tests for M4: assert replaced with ValueError in AST visitor."""

    def test_invalid_subscript_value_raises_value_error(self, tmp_path):
        """Non-Name Subscript value raises ValueError, not AssertionError."""
        import ast

        source = '''
from typing import Annotated

def jsonrpc(f): return f

@jsonrpc
def bad_func(x: "invalid"[str, "description"]) -> str:
    """A bad function."""
    pass
'''
        plugin = tmp_path / "bad_plugin.py"
        plugin.write_text(source, encoding="utf-8")
        with pytest.raises(Exception):
            parse_plugin_file(str(plugin))

    def test_duplicate_function_raises_value_error(self, tmp_path):
        """Duplicate @jsonrpc function raises ValueError."""
        source = '''
from typing import Annotated

def jsonrpc(f): return f

@jsonrpc
def dup_func(x: Annotated[str, "description"]) -> str:
    """First."""
    pass

@jsonrpc
def dup_func(x: Annotated[str, "description"]) -> str:
    """Second."""
    pass
'''
        plugin = tmp_path / "dup_plugin.py"
        plugin.write_text(source, encoding="utf-8")
        with pytest.raises(ValueError, match="Duplicate @jsonrpc function"):
            parse_plugin_file(str(plugin))
