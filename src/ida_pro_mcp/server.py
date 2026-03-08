import os
import sys
import json
import shutil
import argparse
import itertools
import http.client
from urllib.parse import urlparse
from glob import glob
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Multi-instance support (graceful degradation if modules not available)
try:
    from ida_pro_mcp.registry import InstanceRegistry, get_default_registry_path
    from ida_pro_mcp.router import InstanceRouter
    from ida_pro_mcp.cache import get_cache, DEFAULT_MAX_OUTPUT_CHARS
    from ida_pro_mcp.health import cleanup_stale_instances, rediscover_instances
    from ida_pro_mcp.tools.management import (
        list_instances as _list_instances_impl,
        get_cached_output as _get_cached_output_impl,
        refresh_instances as _refresh_instances_impl,
    )
    _HAS_MULTI_INSTANCE = True
except ImportError:
    _HAS_MULTI_INSTANCE = False

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

# Thread-safe JSON-RPC request ID counter
_jsonrpc_id_counter = itertools.count(1)
ida_host = "127.0.0.1"
ida_port = 13337

# Multi-instance state (initialized in main() when --multi is active)
_registry: "InstanceRegistry | None" = None
_router: "InstanceRouter | None" = None
_multi_instance_mode = False

def make_jsonrpc_request(method: str, *params, instance_id: str | None = None):
    """Make a JSON-RPC request to the IDA plugin.

    In multi-instance mode, routes through InstanceRouter when
    ``instance_id`` is provided or auto-routes to the single instance.
    In single-instance mode (default), connects directly to ida_host:ida_port.
    """
    global ida_host, ida_port, _router, _multi_instance_mode

    # Multi-instance: route through InstanceRouter
    if _multi_instance_mode and _router is not None:
        rpc_params = {
            "arguments": {"instance_id": instance_id} if instance_id else {},
            "method_params": list(params),
        }
        result = _router.route_request(method, rpc_params)

        # Check for router-level errors
        if isinstance(result, dict) and "error" in result:
            error_msg = result["error"]
            hint = result.get("hint", "")
            msg = f"Router error: {error_msg}"
            if hint:
                msg += f"\nHint: {hint}"
            # Include available instances for discoverability
            if "available_instances" in result:
                msg += f"\nAvailable instances: {json.dumps(result['available_instances'], indent=2)}"
            if "replacements" in result:
                msg += f"\nReplacements: {json.dumps(result['replacements'], indent=2)}"
            raise Exception(msg)

        # Normalize empty results
        if result is None:
            result = "success"
        return result

    # Single-instance: direct connection
    conn = http.client.HTTPConnection(ida_host, ida_port, timeout=300.0)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": next(_jsonrpc_id_counter),
    }

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        data = json.loads(response.read().decode())

        if "error" in data:
            error = data["error"]
            code = error["code"]
            message = error["message"]
            pretty = f"JSON-RPC error {code}: {message}"
            if "data" in error:
                pretty += "\n" + error["data"]
            raise Exception(pretty)

        result = data["result"]
        # NOTE: LLMs do not respond well to empty responses
        if result is None:
            result = "success"
        return result
    except ConnectionRefusedError:
        raise Exception(
            f"Connection refused to IDA at {ida_host}:{ida_port}. "
            f"Is the MCP plugin running? Use Edit -> Plugins -> MCP to start it."
        )
    except (TimeoutError, OSError) as e:
        raise Exception(
            f"Connection to IDA at {ida_host}:{ida_port} timed out. "
            f"IDA may be busy with a long operation (single-threaded). "
            f"Wait and retry. ({type(e).__name__})"
        )
    finally:
        conn.close()

@mcp.tool()
def check_connection(instance_id: Optional[str] = None) -> str:
    """Check if the IDA plugin is running"""
    try:
        metadata = make_jsonrpc_request("get_metadata", instance_id=instance_id)
        return f"Successfully connected to IDA Pro (open file: {metadata['module']})"
    except Exception as e:
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?"

# Tool registry: AST-based tool extraction from mcp-plugin.py
from ida_pro_mcp.tool_registry import (
    parse_plugin_file,
    generate_code,
    write_generated_file,
    generate_tool_schemas,
)

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
parse_result = parse_plugin_file(IDA_PLUGIN_PY)
code = generate_code(parse_result)
write_generated_file(code, GENERATED_PY)

exec(compile(code, GENERATED_PY, "exec"))

MCP_FUNCTIONS = ["check_connection"] + list(parse_result.functions.keys())
UNSAFE_FUNCTIONS = parse_result.unsafe
SAFE_FUNCTIONS = [f for f in MCP_FUNCTIONS if f not in UNSAFE_FUNCTIONS]

# Management tools are always safe (read-only operations)
MANAGEMENT_FUNCTIONS = ["list_instances", "get_cached_output", "refresh_instances"]
SAFE_FUNCTIONS = SAFE_FUNCTIONS + MANAGEMENT_FUNCTIONS

def generate_readme():
    print("README:")
    print(f"- `check_connection()`: Check if the IDA plugin is running.")
    def get_description(name: str):
        function = parse_result.functions[name]
        signature = function.name + "("
        for i, arg in enumerate(function.args.args):
            if i > 0:
                signature += ", "
            signature += arg.arg
        signature += ")"
        description = parse_result.descriptions.get(function.name, "<no description>").strip().split("\n")[0]
        if description[-1] != ".":
            description += "."
        return f"- `{signature}`: {description}"
    for safe_function in SAFE_FUNCTIONS:
        if safe_function != "check_connection" and safe_function in parse_result.functions:
            print(get_description(safe_function))
    print("\nUnsafe functions (`--unsafe` flag required):\n")
    for unsafe_function in UNSAFE_FUNCTIONS:
        print(get_description(unsafe_function))
    print("\nMCP Config:")
    mcp_config = {
        "mcpServers": {
            "github.com/mrexodia/ida-pro-mcp": {
            "command": "uv",
            "args": [
                "--directory",
                "c:\\MCP\\ida-pro-mcp",
                "run",
                "server.py",
                "--install-plugin"
            ],
            "timeout": 1800,
            "disabled": False,
            }
        }
    }
    print(json.dumps(mcp_config, indent=2))

def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable

def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result

def print_mcp_config():
    mcp_config = {
        "command": get_python_executable(),
        "args": [
            __file__,
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        print(f"[WARNING] Custom Python environment variables detected")
        mcp_config["env"] = env
    print(json.dumps({
            "mcpServers": {
                mcp.name: mcp_config
            }
        }, indent=2)
    )

def install_mcp_servers(*, uninstall=False, quiet=False, env={}):
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA", ""), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                data = f.read().strip()
                if len(data) == 0:
                    config = {}
                else:
                    try:
                        config = json.loads(data)
                    except json.decoder.JSONDecodeError:
                        if not quiet:
                            print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                        continue
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        mcp_servers = config["mcpServers"]
        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]
        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[mcp.name]
        else:
            # Copy environment variables from the existing server if present
            if mcp.name in mcp_servers:
                for key, value in mcp_servers[mcp.name].get("env", {}).items():
                    env[key] = value
            if copy_python_env(env):
                print(f"[WARNING] Custom Python environment variables detected")
            mcp_servers[mcp.name] = {
                "command": get_python_executable(),
                "args": [
                    __file__,
                ],
                "timeout": 1800,
                "disabled": False,
                "autoApprove": SAFE_FUNCTIONS,
                "alwaysAllow": SAFE_FUNCTIONS,
            }
            if env:
                mcp_servers[mcp.name]["env"] = env
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1
    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    free_licenses = glob(os.path.join(ida_folder, "idafree_*.hexlic"))
    if len(free_licenses) > 0:
        print(f"IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
        sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")
    if uninstall:
        if not os.path.exists(plugin_destination):
            print(f"Skipping IDA plugin uninstall\n  Path: {plugin_destination} (not found)")
            return
        os.remove(plugin_destination)
        if not quiet:
            print(f"Uninstalled IDA plugin\n  Path: {plugin_destination}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Skip if symlink already up to date
        realpath = os.path.realpath(plugin_destination)
        if realpath == IDA_PLUGIN_PY:
            if not quiet:
                print(f"Skipping IDA plugin installation (symlink up to date)\n  Plugin: {realpath}")
        else:
            # Remove existing plugin
            if os.path.lexists(plugin_destination):
                os.remove(plugin_destination)

            # Symlink or copy the plugin
            try:
                os.symlink(IDA_PLUGIN_PY, plugin_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_PY, plugin_destination)

            if not quiet:
                print(f"Installed IDA Pro plugin (IDA restart required)\n  Plugin: {plugin_destination}")

def _init_multi_instance() -> bool:
    """Initialize multi-instance mode: registry, health checks, auto-discovery.

    Returns:
        True if multi-instance mode was successfully initialized.
    """
    global _registry, _router, _multi_instance_mode

    if not _HAS_MULTI_INSTANCE:
        print(
            "[ida-pro-mcp] Multi-instance modules not available. "
            "Running in single-instance mode.",
            file=sys.stderr,
        )
        return False

    try:
        _registry = InstanceRegistry()

        # Startup health check: remove dead instances
        removed = cleanup_stale_instances(_registry)
        if removed:
            print(
                f"[ida-pro-mcp] Cleaned up {len(removed)} dead instance(s): {removed}",
                file=sys.stderr,
            )

        # Auto-discover running IDA instances
        instances = _registry.list_instances()
        if not instances:
            print("[ida-pro-mcp] No instances in registry, attempting auto-discovery...", file=sys.stderr)
            discovered = rediscover_instances(_registry)
            if discovered:
                print(f"[ida-pro-mcp] Auto-discovered {len(discovered)} instance(s): {discovered}", file=sys.stderr)
            else:
                print("[ida-pro-mcp] No IDA instances found. Tools will be available once IDA connects.", file=sys.stderr)
        else:
            print(f"[ida-pro-mcp] Found {len(instances)} registered instance(s).", file=sys.stderr)

        _router = InstanceRouter(_registry)
        _multi_instance_mode = True

        # Register management tools
        _register_management_tools()

        return True
    except Exception as e:
        print(
            f"[ida-pro-mcp] Failed to initialize multi-instance mode: {e}. "
            f"Falling back to single-instance mode.",
            file=sys.stderr,
        )
        _registry = None
        _router = None
        _multi_instance_mode = False
        return False


def _register_management_tools():
    """Register multi-instance management tools with the MCP server."""
    global _registry

    @mcp.tool()
    def list_instances() -> str:
        """List all registered IDA instances.

        Returns information about all active IDA Pro instances including
        their instance ID, binary name, architecture, host, port, and
        registration time. Use the returned instance_id values in other
        tool calls to target a specific instance.
        """
        result = _list_instances_impl(_registry)
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    def get_cached_output(
        cache_id: str,
        offset: int = 0,
        size: int = 50000,
    ) -> str:
        """Retrieve cached output from a previous tool call.

        When a tool response is too large, it is cached and a cache_id is
        returned. Use this tool to retrieve the full output in pages.
        """
        result = _get_cached_output_impl(cache_id, offset=offset, size=size)
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    def refresh_instances() -> str:
        """Refresh the instance registry.

        Removes dead instances and auto-discovers running IDA instances
        with MCP plugins. Call this when you expect IDA instances to have
        started or stopped.
        """
        result = _refresh_instances_impl(_registry)
        return json.dumps(result, indent=2, ensure_ascii=False)


def main():
    global ida_host, ida_port, _multi_instance_mode
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the MCP Server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the MCP Server and IDA plugin")
    parser.add_argument("--generate-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-plugin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--ida-rpc", type=str, default=f"http://{ida_host}:{ida_port}", help=f"IDA RPC server to use (default: http://{ida_host}:{ida_port})")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("--config", action="store_true", help="Generate MCP config JSON")
    parser.add_argument(
        "--multi", action="store_true",
        help="Enable multi-instance mode (auto-detect and route to multiple IDA instances)",
    )
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin()
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    # NOTE: Developers can use this to generate the README
    if args.generate_docs:
        generate_readme()
        return

    # NOTE: This is silent for automated Cline installations
    if args.install_plugin:
        install_ida_plugin(quiet=True)

    if args.config:
        print_mcp_config()
        return

    # Multi-instance mode: auto-detection or explicit --multi flag
    if args.multi:
        _init_multi_instance()
    elif _HAS_MULTI_INSTANCE:
        # Auto-detection: check if registry file exists with instances
        try:
            registry_path = get_default_registry_path()
            if os.path.exists(registry_path):
                with open(registry_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get("instances"):
                    print(
                        "[ida-pro-mcp] Registry file found with instances, "
                        "auto-enabling multi-instance mode.",
                        file=sys.stderr,
                    )
                    _init_multi_instance()
        except Exception:
            pass  # Silently fall through to single-instance mode

    # Single-instance mode: parse IDA RPC server argument
    if not _multi_instance_mode:
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        ida_host = ida_rpc.hostname
        ida_port = ida_rpc.port

    # Remove unsafe tools
    if not args.unsafe:
        mcp_tools = mcp._tool_manager._tools
        for unsafe in UNSAFE_FUNCTIONS:
            if unsafe in mcp_tools:
                del mcp_tools[unsafe]

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            mode_label = "multi-instance" if _multi_instance_mode else "single-instance"
            print(f"MCP Server available at http://{mcp.settings.host}:{mcp.settings.port}/sse ({mode_label} mode)")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
