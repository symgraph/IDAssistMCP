"""
Static catalog of all IDAssistMCP MCP tools with metadata.

No PySide6 imports — usable by both UI and server-side code.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ToolInfo:
    """Metadata for a single MCP tool."""
    name: str
    display_name: str
    category: str
    description: str
    annotation: str  # "read_only", "modify", or "non_idempotent"


# Complete catalog of all 39 MCP tools
TOOL_CATALOG: List[ToolInfo] = [
    # Binary Management (2)
    ToolInfo("list_binaries", "List Binaries", "Binary Management", "List the currently loaded binary", "read_only"),
    ToolInfo("get_binary_info", "Get Binary Info", "Binary Management", "Get detailed binary metadata", "read_only"),

    # Code Analysis (4)
    ToolInfo("get_code", "Get Code", "Code Analysis", "Get function code (decompile or disasm format)", "read_only"),
    ToolInfo("analyze_function", "Analyze Function", "Code Analysis", "Comprehensive function analysis with CFG, callers, decompilation", "read_only"),
    ToolInfo("get_function_signature", "Function Signature", "Code Analysis", "Get the native byte signature for a function", "read_only"),
    ToolInfo("get_basic_blocks", "Get Basic Blocks", "Code Analysis", "Get basic blocks (CFG) for a function", "read_only"),

    # Consolidated Tools (4)
    ToolInfo("xrefs_tool", "Cross-References", "Cross-References", "Get xrefs to/from address, optionally include callers/callees", "read_only"),
    ToolInfo("comments_tool", "Comments", "Comments & Variables", "Get, set, list, or remove comments (action parameter)", "modify"),
    ToolInfo("variables_tool", "Variables", "Comments & Variables", "List variables or rename local/global variables (action parameter)", "modify"),
    ToolInfo("types_tool", "Types", "Types", "List, set, create_struct, or create_enum (action parameter)", "modify"),

    # Function Discovery (5)
    ToolInfo("get_functions", "Get Functions", "Function Discovery", "List all functions with filtering and pagination", "read_only"),
    ToolInfo("search_functions_by_name", "Search Functions", "Function Discovery", "Search functions by name pattern and size filters", "read_only"),
    ToolInfo("get_function_by_name", "Get Function by Name", "Function Discovery", "Look up function by exact name", "read_only"),
    ToolInfo("get_function_by_address", "Get Function by Address", "Function Discovery", "Look up function at address", "read_only"),
    ToolInfo("get_function_statistics", "Function Statistics", "Function Discovery", "Get statistics about all functions", "read_only"),

    # Symbol Management (2)
    ToolInfo("rename_symbol", "Rename Symbol", "Symbol Management", "Rename any symbol (function or data)", "modify"),
    ToolInfo("batch_rename", "Batch Rename", "Symbol Management", "Batch rename multiple symbols", "modify"),

    # Binary Info (5)
    ToolInfo("get_imports", "Get Imports", "Binary Info", "Get imported functions by module", "read_only"),
    ToolInfo("get_exports", "Get Exports", "Binary Info", "Get exported symbols", "read_only"),
    ToolInfo("get_strings", "Get Strings", "Binary Info", "Get strings with pagination", "read_only"),
    ToolInfo("get_segments", "Get Segments", "Binary Info", "Get memory segments with permissions", "read_only"),
    ToolInfo("get_entry_points", "Get Entry Points", "Binary Info", "Get all binary entry points", "read_only"),

    # Data Analysis (4)
    ToolInfo("read_memory", "Read Memory", "Data Analysis", "Read raw bytes from the IDB", "read_only"),
    ToolInfo("get_data_at", "Get Data At", "Data Analysis", "Get typed data at address", "read_only"),
    ToolInfo("search_bytes", "Search Bytes", "Data Analysis", "Search for byte pattern", "read_only"),
    ToolInfo("search_strings", "Search Strings", "Data Analysis", "Search strings by pattern", "read_only"),

    # Patching (1)
    ToolInfo("patch_bytes", "Patch Bytes", "Patching", "Patch bytes in the IDB", "non_idempotent"),

    # Navigation (4)
    ToolInfo("navigate_to", "Navigate To", "Navigation", "Move IDA cursor to address", "modify"),
    ToolInfo("set_bookmark", "Set Bookmark", "Navigation", "Create a position bookmark", "modify"),
    ToolInfo("get_current_address", "Get Current Address", "Navigation", "Get address at cursor position", "read_only"),
    ToolInfo("get_current_function", "Get Current Function", "Navigation", "Get function at cursor position", "read_only"),

    # New Feature Parity Tools (3)
    ToolInfo("get_function_stack_layout", "Stack Layout", "Code Analysis", "Get stack frame layout for a function", "read_only"),
    ToolInfo("get_classes", "Get Classes", "Types", "Get struct/class types from type library", "read_only"),
    ToolInfo("create_data_var", "Create Data Var", "Data Analysis", "Define a data variable at address", "modify"),
    ToolInfo("get_data_vars", "Get Data Vars", "Data Analysis", "Get defined data variables (non-code items)", "read_only"),

    # Task Management (4)
    ToolInfo("start_task", "Start Task", "Task Management", "Start an async background task", "non_idempotent"),
    ToolInfo("get_task_status", "Get Task Status", "Task Management", "Get status of async task", "read_only"),
    ToolInfo("cancel_task", "Cancel Task", "Task Management", "Cancel a running async task", "modify"),
    ToolInfo("list_tasks", "List Tasks", "Task Management", "List all async tasks", "read_only"),
]

# Build lookup indexes
_TOOLS_BY_NAME: Dict[str, ToolInfo] = {t.name: t for t in TOOL_CATALOG}


def get_tool_info(name: str) -> ToolInfo | None:
    """Get tool info by name."""
    return _TOOLS_BY_NAME.get(name)


def get_tool_names() -> List[str]:
    """Get all tool names."""
    return [t.name for t in TOOL_CATALOG]


def get_tools_by_category() -> Dict[str, List[ToolInfo]]:
    """Get tools grouped by category."""
    result: Dict[str, List[ToolInfo]] = {}
    for tool in TOOL_CATALOG:
        result.setdefault(tool.category, []).append(tool)
    return result


def get_read_only_tool_names() -> List[str]:
    """Get names of all read-only tools."""
    return [t.name for t in TOOL_CATALOG if t.annotation == "read_only"]
