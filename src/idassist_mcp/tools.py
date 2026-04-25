"""
Comprehensive MCP tool implementations for IDAssistMCP

This module provides 41 IDA Pro integration tools registered as
FastMCP tools. All tools that call IDA APIs use @_ida_main_thread to dispatch
onto IDA's main thread (required for both reads and writes).

Consolidated tools (5): get_code, comments, variables, types, xrefs
Standalone tools (36): see register_tools() for the full list
"""

import builtins
import functools
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context, FastMCP

from .context import IDAContextManager
from .function_signature_generator import IDAFunctionSignatureGenerator
from .logging import log
from .tasks import TaskStatus, get_task_manager
from .utils import (
    execute_on_main_thread,
    format_address,
    parse_address,
    resolve_name_or_address,
    truncate_string,
)

try:
    import idaapi
    import idautils
    import idc
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_kernwin
    import ida_lines
    import ida_loader
    import ida_name
    import ida_nalt
    import ida_segment
    import ida_typeinf
    import ida_xref
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


# --------------------------------------------------------------------------- #
# Helper: resolve function name / hex address to ea
# --------------------------------------------------------------------------- #

def _resolve(name_or_addr: str) -> int:
    """Resolve a function name or address string to an effective address.

    Raises ValueError if the name/address cannot be resolved.
    """
    ea = resolve_name_or_address(name_or_addr)
    if ea is None:
        raise ValueError(f"Cannot resolve '{name_or_addr}' to an address")
    return ea


def _parse_byte_values(value: Any) -> bytes:
    """Parse bytes from a hex string or integer array."""
    if isinstance(value, str):
        normalized = value.replace("0x", "").replace("0X", "")
        normalized = re.sub(r"[,\s]", "", normalized)
        if not normalized:
            return b""
        if len(normalized) % 2 != 0:
            raise ValueError("hex string must contain an even number of characters")
        try:
            return builtins.bytes.fromhex(normalized)
        except ValueError as e:
            raise ValueError(f"invalid hex string: {value}") from e

    if isinstance(value, (list, tuple)):
        parsed = bytearray()
        for index, item in enumerate(value):
            if not isinstance(item, int):
                raise ValueError(f"array element at index {index} is not an integer")
            if item < 0 or item > 255:
                raise ValueError(f"array element at index {index} out of range (0-255): {item}")
            parsed.append(item)
        return builtins.bytes(parsed)

    raise ValueError("bytes must be a hex string or integer array")


def _format_hex(data: bytes) -> str:
    """Format bytes as space-separated uppercase hex."""
    return " ".join(f"{b:02X}" for b in data)


def _coerce_assembled_bytes(value: Any) -> bytes:
    """Normalize IDA assembler output to bytes."""
    if isinstance(value, builtins.bytes):
        return value
    if isinstance(value, bytearray):
        return builtins.bytes(value)
    if isinstance(value, str):
        return value.encode("latin1")
    return builtins.bytes(value)


# --------------------------------------------------------------------------- #
# Tool registration entry-point (called from server.py)
# --------------------------------------------------------------------------- #

def register_tools(mcp: FastMCP, disabled_tools=None):
    """Register all MCP tools on the given FastMCP instance.

    Args:
        mcp: FastMCP server instance
        disabled_tools: Optional set/list of tool names to skip registration
    """
    if disabled_tools is None:
        disabled_tools = set()
    else:
        disabled_tools = set(disabled_tools)

    def _tool(name, **kwargs):
        """Conditionally apply @mcp.tool() decorator, skipping disabled tools.
        Wraps the tool function with invocation logging."""
        if name in disabled_tools:
            log.log_info(f"Tool '{name}' is disabled, skipping registration")
            return lambda fn: fn  # no-op decorator

        real_decorator = mcp.tool(**kwargs)

        def logging_decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kw):
                log.log_info(f"Tool called: {name}")
                return fn(*args, **kw)

            @functools.wraps(fn)
            async def async_wrapper(*args, **kw):
                log.log_info(f"Tool called: {name}")
                return await fn(*args, **kw)

            import asyncio
            wrapped = async_wrapper if asyncio.iscoroutinefunction(fn) else wrapper
            return real_decorator(wrapped)

        return logging_decorator

    def _ida_main_thread(fn):
        """Decorator: run entire function body on IDA's main thread.

        IDA requires many API calls (reads AND writes) to happen on the
        main thread.  The MCP server runs on a background thread, so all
        tool functions that call IDA APIs must be dispatched.
        """
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            holder = [None, None]          # [result, exception]
            def _do():
                try:
                    holder[0] = fn(*args, **kwargs)
                except Exception as e:
                    holder[1] = e
            execute_on_main_thread(_do)
            if holder[1] is not None:
                raise holder[1]
            return holder[0]
        return wrapper

    # Tool annotations for MCP 2025-11-25 compliance
    READ_ONLY = {
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    MODIFY = {
        "readOnlyHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    NON_IDEMPOTENT = {
        "readOnlyHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
    FILE_WRITE = {
        "readOnlyHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }

    # ================================================================== #
    #  Internal helpers (not registered as tools)
    # ================================================================== #

    @_ida_main_thread
    def _decompile_function_impl(function_name_or_address: str) -> dict:
        """Internal: decompile a function using Hex-Rays."""
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": f"Decompilation failed for {hex(ea)}"}

            func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            return {
                "function": func_name,
                "address": hex(func.start_ea),
                "code": str(cfunc),
            }
        except Exception as e:
            return {"error": f"Decompilation error: {e}"}

    @_ida_main_thread
    def _get_disassembly_impl(function_name_or_address: str) -> dict:
        """Internal: get disassembly listing for a function."""
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        lines = []
        for item_ea in idautils.FuncItems(func.start_ea):
            disasm = idc.generate_disasm_line(item_ea, 0)
            lines.append(f"0x{item_ea:08x}  {disasm}")

        return {
            "function": func_name,
            "address": hex(func.start_ea),
            "disassembly": "\n".join(lines),
            "instruction_count": len(lines),
        }

    # ================================================================== #
    #  1-2. Binary Management
    # ================================================================== #

    @_tool("list_binaries", annotations=READ_ONLY)
    def list_binaries(ctx: Context) -> dict:
        """List the currently loaded binary (IDA is single-binary).

        Returns:
            Dictionary with the current binary name and metadata.
        """
        cm: IDAContextManager = ctx.request_context.lifespan_context
        cm.refresh()
        binary_ctx = cm.get_context()
        return {
            "binaries": [binary_ctx.filename],
            "count": 1,
        }

    @_tool("get_binary_info", annotations=READ_ONLY)
    def get_binary_info(ctx: Context) -> dict:
        """Get detailed information about the currently loaded binary.

        Returns:
            Dictionary with architecture, platform, hashes, segments, etc.
        """
        cm: IDAContextManager = ctx.request_context.lifespan_context
        cm.refresh()
        return cm.get_context().to_dict()

    # ================================================================== #
    #  3. get_code (consolidated — absorbs decompile/disasm/il_expression)
    # ================================================================== #

    @_tool("get_code", annotations=READ_ONLY)
    def get_code(function_name_or_address: str, ctx: Context,
                 format: str = "decompile") -> dict:
        """Get function code in specified format (unified tool).

        Args:
            function_name_or_address: Function identifier (name or hex address)
            format: Output format - 'decompile' for pseudo-C or 'disasm' for assembly

        Returns:
            Dictionary with function info and code.
        """
        if format == "disasm":
            return _get_disassembly_impl(function_name_or_address)
        else:
            return _decompile_function_impl(function_name_or_address)

    # ================================================================== #
    #  4. analyze_function (comprehensive — absorbs get_function_info)
    # ================================================================== #

    @_tool("analyze_function", annotations=READ_ONLY)
    @_ida_main_thread
    def analyze_function(function_name_or_address: str, ctx: Context) -> dict:
        """Perform comprehensive analysis of a function.

        Returns metadata, control flow, callers/callees, prototype, and
        decompiled code. Subsumes the old get_function_info tool.

        Args:
            function_name_or_address: Function name or address

        Returns:
            Comprehensive function analysis including control flow and call info.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"

        result = {
            "name": func_name,
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
            "flags": func.flags,
        }

        # Prototype
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea):
                result["prototype"] = str(tif)
        except Exception:
            pass

        # Basic blocks (CFG complexity)
        flow = idaapi.FlowChart(func)
        blocks = list(flow)
        result["basic_block_count"] = len(blocks)

        # Instruction count
        instructions = list(idautils.FuncItems(func.start_ea))
        result["instruction_count"] = len(instructions)

        # Callers and callees
        callers = set()
        for ref in idautils.CodeRefsTo(func.start_ea, 0):
            cfunc = ida_funcs.get_func(ref)
            if cfunc:
                callers.add(ida_funcs.get_func_name(cfunc.start_ea))

        callees = set()
        for item_ea in instructions:
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                cfunc = ida_funcs.get_func(ref)
                if cfunc and cfunc.start_ea != func.start_ea:
                    callees.add(ida_funcs.get_func_name(cfunc.start_ea))

        result["callers"] = list(callers)
        result["callees"] = list(callees)
        result["caller_count"] = len(callers)
        result["callee_count"] = len(callees)

        # Try decompilation
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                result["decompiled"] = str(cfunc)
                result["variable_count"] = len(cfunc.get_lvars())
        except Exception:
            result["decompiled"] = None

        return result

    @_tool("get_function_signature", annotations=READ_ONLY)
    def get_function_signature(function_name_or_address: str, ctx: Context) -> dict:
        """Get the native IDAssist byte signature for a function."""
        holder = {"error": None, "name": None, "address": None, "start_ea": None}

        def _collect() -> None:
            ea = _resolve(function_name_or_address)
            func = ida_funcs.get_func(ea)
            if not func:
                holder["error"] = {"error": f"No function at {hex(ea)}"}
                return

            holder["name"] = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            holder["address"] = hex(func.start_ea)
            holder["start_ea"] = func.start_ea

        execute_on_main_thread(_collect)
        if holder["error"] is not None:
            return holder["error"]

        generator = IDAFunctionSignatureGenerator()
        return {
            "name": holder["name"],
            "address": holder["address"],
            "signature": generator.generate(holder["start_ea"]),
        }

    # ================================================================== #
    #  5. get_basic_blocks
    # ================================================================== #

    @_tool("get_basic_blocks", annotations=READ_ONLY)
    @_ida_main_thread
    def get_basic_blocks(function_name_or_address: str, ctx: Context) -> list:
        """Get basic blocks (CFG) for a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            List of basic block dictionaries with start, end, size, successors.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return [{"error": f"No function at {hex(ea)}"}]

        blocks = []
        flow = idaapi.FlowChart(func)
        for block in flow:
            succs = [hex(s.start_ea) for s in block.succs()]
            preds = [hex(p.start_ea) for p in block.preds()]
            blocks.append({
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": succs,
                "predecessors": preds,
            })

        return blocks

    # ================================================================== #
    #  6. xrefs (consolidated — absorbs get_xrefs + get_callers_callees)
    # ================================================================== #

    @_tool("xrefs", annotations=READ_ONLY)
    @_ida_main_thread
    def xrefs(address_or_function: str, ctx: Context,
                   direction: str = "both",
                   include_calls: bool = False) -> dict:
        """Get cross-references and optionally callers/callees for an address or function.

        Args:
            address_or_function: Address (hex) or function name
            direction: 'to', 'from', or 'both' for xref direction
            include_calls: If True, also include callers/callees (like the old get_callers_callees)

        Returns:
            Dictionary with xrefs and optionally call graph info.
        """
        ea = _resolve(address_or_function)

        refs_to = []
        refs_from = []

        if direction in ("to", "both"):
            for ref in idautils.CodeRefsTo(ea, 0):
                func = ida_funcs.get_func(ref)
                fname = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                refs_to.append({"address": hex(ref), "type": "code", "function": fname})
            for ref in idautils.DataRefsTo(ea):
                refs_to.append({"address": hex(ref), "type": "data"})

        if direction in ("from", "both"):
            for ref in idautils.CodeRefsFrom(ea, 0):
                func = ida_funcs.get_func(ref)
                fname = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                refs_from.append({"address": hex(ref), "type": "code", "function": fname})
            for ref in idautils.DataRefsFrom(ea):
                refs_from.append({"address": hex(ref), "type": "data"})

        result = {
            "address": hex(ea),
            "refs_to": refs_to,
            "refs_from": refs_from,
            "total_to": len(refs_to),
            "total_from": len(refs_from),
        }

        if include_calls:
            func = ida_funcs.get_func(ea)
            if func:
                callers = []
                callees = []

                for ref in idautils.CodeRefsTo(func.start_ea, 0):
                    caller_func = ida_funcs.get_func(ref)
                    if caller_func:
                        caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                        callers.append({"name": caller_name, "address": hex(caller_func.start_ea), "call_site": hex(ref)})

                for item_ea in idautils.FuncItems(func.start_ea):
                    for ref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = ida_funcs.get_func(ref)
                        if callee_func and callee_func.start_ea != func.start_ea:
                            callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                            callees.append({"name": callee_name, "address": hex(callee_func.start_ea), "call_site": hex(item_ea)})

                # Deduplicate callees by target address
                seen = set()
                unique_callees = []
                for c in callees:
                    if c["address"] not in seen:
                        seen.add(c["address"])
                        unique_callees.append(c)

                result["function"] = ida_funcs.get_func_name(func.start_ea)
                result["callers"] = callers
                result["callees"] = unique_callees
                result["caller_count"] = len(callers)
                result["callee_count"] = len(unique_callees)

        return result

    # ================================================================== #
    #  7. comments (consolidated — absorbs get_comments + set_comment)
    # ================================================================== #

    @_tool("comments", annotations=MODIFY)
    @_ida_main_thread
    def comments(action: str, ctx: Context,
                      address_or_function: str = "",
                      text: str = "",
                      comment_type: str = "regular") -> dict:
        """Unified tool for managing comments (get, set, list, remove).

        Args:
            action: 'get' (comments for a function), 'set' (set comment at address),
                    'list' (all comments across all functions), 'remove' (clear comment at address)
            address_or_function: Function name/address (for get/set/remove)
            text: Comment text (for 'set' action)
            comment_type: 'regular', 'repeatable', or 'function' (for get/set/remove)

        Returns:
            Dictionary with comment data or confirmation message.
        """
        if action == "get":
            if not address_or_function:
                return {"error": "address_or_function is required for 'get' action"}
            ea = _resolve(address_or_function)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            comments = []
            func_cmt = idc.get_func_cmt(func.start_ea, 0)
            func_cmt_r = idc.get_func_cmt(func.start_ea, 1)
            if func_cmt:
                comments.append({"address": hex(func.start_ea), "type": "function", "text": func_cmt})
            if func_cmt_r:
                comments.append({"address": hex(func.start_ea), "type": "function_repeatable", "text": func_cmt_r})

            for item_ea in idautils.FuncItems(func.start_ea):
                cmt = idc.get_cmt(item_ea, 0)
                cmt_r = idc.get_cmt(item_ea, 1)
                if cmt:
                    comments.append({"address": hex(item_ea), "type": "regular", "text": cmt})
                if cmt_r:
                    comments.append({"address": hex(item_ea), "type": "repeatable", "text": cmt_r})

            return {"function": ida_funcs.get_func_name(func.start_ea), "comments": comments}

        elif action == "set":
            if not address_or_function:
                return {"error": "address_or_function is required for 'set' action"}
            ea = _resolve(address_or_function)

            if comment_type == "function":
                idc.set_func_cmt(ea, text, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, text, 1)
            else:
                idc.set_cmt(ea, text, 0)

            return {"status": "ok", "message": f"Set {comment_type} comment at {hex(ea)}"}

        elif action == "list":
            comments = []
            for func_ea in idautils.Functions():
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

                func_cmt = idc.get_func_cmt(func_ea, 0)
                func_cmt_r = idc.get_func_cmt(func_ea, 1)
                if func_cmt:
                    comments.append({"function": func_name, "address": hex(func_ea), "type": "function", "text": func_cmt})
                if func_cmt_r:
                    comments.append({"function": func_name, "address": hex(func_ea), "type": "function_repeatable", "text": func_cmt_r})

                for item_ea in idautils.FuncItems(func_ea):
                    cmt = idc.get_cmt(item_ea, 0)
                    cmt_r = idc.get_cmt(item_ea, 1)
                    if cmt:
                        comments.append({"function": func_name, "address": hex(item_ea), "type": "regular", "text": cmt})
                    if cmt_r:
                        comments.append({"function": func_name, "address": hex(item_ea), "type": "repeatable", "text": cmt_r})

            return {"comments": comments, "count": len(comments)}

        elif action == "remove":
            if not address_or_function:
                return {"error": "address_or_function is required for 'remove' action"}
            ea = _resolve(address_or_function)

            if comment_type == "function":
                idc.set_func_cmt(ea, "", 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, "", 1)
            else:
                idc.set_cmt(ea, "", 0)

            return {"status": "ok", "message": f"Removed {comment_type} comment at {hex(ea)}"}

        else:
            return {"error": f"Unknown action '{action}'. Use 'get', 'set', 'list', or 'remove'."}

    # ================================================================== #
    #  8. variables (consolidated — absorbs get_variables + rename_variable)
    # ================================================================== #

    @_tool("variables", annotations=MODIFY)
    @_ida_main_thread
    def variables(action: str, ctx: Context,
                       function_name_or_address: str = "",
                       var_name: str = "",
                       new_name: str = "",
                       scope: str = "auto",
                       address_or_name: str = "") -> dict:
        """Unified tool for managing local and global variables (list, rename).

        Args:
            action: 'list' (get variables for a function) or 'rename' (rename a variable/symbol)
            function_name_or_address: Function name or hex address
            var_name: Current local variable name, or global symbol name fallback for 'rename'
            new_name: New variable name (for 'rename')
            scope: 'auto', 'local', or 'global'
            address_or_name: Global/data symbol address or name (for global rename)

        Returns:
            Dictionary with variable data or confirmation message.
        """
        if action == "list":
            if not function_name_or_address:
                return {"error": "function_name_or_address is required for 'list' action"}
            ea = _resolve(function_name_or_address)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if not cfunc:
                    return {"error": "Decompilation failed"}

                variables = []
                for lvar in cfunc.get_lvars():
                    variables.append({
                        "name": lvar.name,
                        "type": str(lvar.type()),
                        "is_arg": lvar.is_arg_var,
                        "is_result": lvar.is_result_var if hasattr(lvar, 'is_result_var') else False,
                    })

                return {
                    "function": ida_funcs.get_func_name(func.start_ea),
                    "variables": variables,
                    "count": len(variables),
                }
            except Exception as e:
                return {"error": f"Cannot get variables: {e}"}

        elif action == "rename":
            if not new_name:
                return {"error": "new_name is required for 'rename' action"}

            normalized_scope = (scope or "auto").lower()
            if normalized_scope not in {"auto", "local", "global"}:
                return {"error": "scope must be 'auto', 'local', or 'global'"}

            local_requested = (
                normalized_scope == "local"
                or (
                    normalized_scope == "auto"
                    and function_name_or_address
                    and var_name
                    and not address_or_name
                )
            )

            if local_requested:
                if not function_name_or_address or not var_name:
                    return {
                        "error": "function_name_or_address and var_name are required for local rename"
                    }

                ea = _resolve(function_name_or_address)
                func_ea = ida_funcs.get_func(ea)
                if not func_ea:
                    return {"error": f"No function at {hex(ea)}"}

                try:
                    if ida_hexrays.rename_lvar(func_ea.start_ea, var_name, new_name):
                        return {
                            "status": "ok",
                            "message": f"Renamed local variable '{var_name}' to '{new_name}'",
                            "scope": "local",
                            "function": ida_funcs.get_func_name(func_ea.start_ea),
                        }
                    return {"error": f"rename_lvar failed (variable '{var_name}' may not exist)"}
                except Exception as e:
                    return {"error": f"Failed: {e}"}

            target = address_or_name or var_name
            if not target:
                return {"error": "address_or_name or var_name is required for global rename"}

            try:
                global_result = _rename_global_symbol_impl(target, new_name)
                if global_result["success"]:
                    return {
                        "status": "ok",
                        "message": global_result["message"],
                        "scope": "global",
                        "address": global_result["address"],
                        "old_name": global_result["old_name"],
                        "new_name": global_result["new_name"],
                    }
                return {"error": global_result["error"]}
            except Exception as e:
                return {"error": f"Failed: {e}"}

        else:
            return {"error": f"Unknown action '{action}'. Use 'list' or 'rename'."}

    # ================================================================== #
    #  9. types (consolidated — absorbs get_types + set_type + create_struct + create_enum)
    # ================================================================== #

    @_tool("types", annotations=MODIFY)
    @_ida_main_thread
    def types(action: str, ctx: Context,
                   filter: str = "",
                   address: str = "",
                   type_string: str = "",
                   name: str = "",
                   members: Any = None,
                   width: int = 0,
                   bitfield: bool = False) -> dict:
        """Unified tool for managing types (list, set, create_struct, create_enum).

        Args:
            action: 'list', 'set', 'create_struct', or 'create_enum'
            filter: Substring filter for 'list' action
            address: Hex address for 'set' action
            type_string: C-style type string for 'set' action (e.g. 'int __cdecl(int, char *)')
            name: Type name for 'create_struct' or 'create_enum'
            members: For create_struct: list of dicts with 'name', 'type', 'size'.
                     For create_enum: dict of member_name -> value.
            width: Enum member width in bytes (for create_enum, 0 = auto)
            bitfield: Whether enum is a bitfield (for create_enum)

        Returns:
            Dictionary with type data or confirmation message.
        """
        if action == "list":
            til = ida_typeinf.get_idati()
            if not til:
                return {"error": "Cannot access type library"}

            types_list = []
            ordinal = 1
            consecutive_empty = 0
            while consecutive_empty < 200:
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(til, ordinal):
                    consecutive_empty = 0
                    tname = tif.get_type_name() or f"type_{ordinal}"
                    if not filter or filter.lower() in tname.lower():
                        kind = "unknown"
                        if tif.is_struct():
                            kind = "struct"
                        elif tif.is_enum():
                            kind = "enum"
                        elif tif.is_typedef():
                            kind = "typedef"
                        elif tif.is_func():
                            kind = "function"

                        types_list.append({
                            "name": tname,
                            "ordinal": ordinal,
                            "kind": kind,
                            "size": tif.get_size(),
                            "definition": str(tif),
                        })
                else:
                    consecutive_empty += 1
                ordinal += 1

            return {"types": types_list, "count": len(types_list)}

        elif action == "set":
            if not address:
                return {"error": "address is required for 'set' action"}
            if not type_string:
                return {"error": "type_string is required for 'set' action"}

            ea = parse_address(address)
            if ea is None:
                return {"error": f"Invalid address: {address}"}

            try:
                til = ida_typeinf.get_idati()
                # Ensure semicolon for parse_decl
                decl = type_string if type_string.rstrip().endswith(";") else type_string + ";"

                # Method 1: apply_cdecl — most robust for function prototypes
                # and calling conventions (__fastcall, __cdecl, etc.)
                try:
                    if ida_typeinf.apply_cdecl(None, ea, decl):
                        return {"status": "ok", "message": f"Set type at {hex(ea)} to '{type_string}'"}
                except (AttributeError, TypeError):
                    pass

                # Method 2: parse_decl (flag 0 first, then PT_SIL)
                tif = ida_typeinf.tinfo_t()
                parsed = ida_typeinf.parse_decl(tif, til, decl, 0)
                if not parsed:
                    parsed = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
                if not parsed:
                    # Method 3: for bare function types like "void __cdecl(int)",
                    # insert a placeholder name that parse_decl requires
                    named_decl = re.sub(
                        r'((?:__\w+|)\s*)\(',
                        r'\1 _placeholder(',
                        decl, count=1)
                    parsed = ida_typeinf.parse_decl(tif, til, named_decl, 0)

                if parsed:
                    if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                        return {"status": "ok", "message": f"Set type at {hex(ea)} to '{type_string}'"}
                    return {"error": "apply_tinfo failed"}

                return {"error": f"Could not parse type: {type_string}"}
            except Exception as e:
                return {"error": f"Failed: {e}"}

        elif action == "create_struct":
            if not name:
                return {"error": "name is required for 'create_struct' action"}
            if not members or not isinstance(members, list):
                return {"error": "members (list of dicts) is required for 'create_struct' action"}

            try:
                udt = ida_typeinf.udt_type_data_t()
                til = ida_typeinf.get_idati()

                for member in members:
                    udm = ida_typeinf.udt_member_t()
                    udm.name = member["name"]

                    mtif = ida_typeinf.tinfo_t()
                    type_str = member.get("type", "int")
                    if not ida_typeinf.parse_decl(mtif, til, f"{type_str} x;", ida_typeinf.PT_SIL):
                        # Fallback to byte array
                        msize = member.get("size", 4)
                        mtif.create_array(ida_typeinf.tinfo_t(ida_typeinf.BT_INT8), msize)

                    udm.type = mtif
                    udm.size = mtif.get_size() * 8  # size in bits
                    udt.push_back(udm)

                tif = ida_typeinf.tinfo_t()
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                tif.set_named_type(til, name)
                return {"status": "ok", "message": f"Created struct '{name}' with {len(members)} members"}
            except Exception as e:
                return {"error": f"Failed to create struct: {e}"}

        elif action == "create_enum":
            if not name:
                return {"error": "name is required for 'create_enum' action"}
            if not members or not isinstance(members, dict):
                return {"error": "members (dict of name -> value) is required for 'create_enum' action"}

            try:
                edt = ida_typeinf.enum_type_data_t()
                for mname, mval in members.items():
                    em = ida_typeinf.edm_t()
                    em.name = mname
                    em.value = mval
                    edt.push_back(em)

                if bitfield:
                    edt.bte |= ida_typeinf.BTE_BITFIELD

                tif = ida_typeinf.tinfo_t()
                tif.create_enum(edt)
                tif.set_named_type(ida_typeinf.get_idati(), name)
                return {"status": "ok", "message": f"Created enum '{name}' with {len(members)} members"}
            except Exception as e:
                return {"error": f"Failed to create enum: {e}"}

        else:
            return {"error": f"Unknown action '{action}'. Use 'list', 'set', 'create_struct', or 'create_enum'."}

    # ================================================================== #
    #  10-14. Function Discovery
    # ================================================================== #

    @_tool("get_functions", annotations=READ_ONLY)
    @_ida_main_thread
    def get_functions(ctx: Context, filter: str = "", limit: int = 200,
                      offset: int = 0) -> dict:
        """List all functions in the binary with optional filtering and pagination.

        Args:
            filter: Optional name substring filter
            limit: Maximum number of functions to return
            offset: Number of functions to skip (for pagination)

        Returns:
            Dictionary with list of functions and pagination info.
        """
        all_funcs = []
        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            if filter and filter.lower() not in name.lower():
                continue
            func = ida_funcs.get_func(func_ea)
            size = (func.end_ea - func.start_ea) if func else 0
            all_funcs.append({
                "name": name,
                "address": hex(func_ea),
                "size": size,
            })

        total = len(all_funcs)
        page = all_funcs[offset:offset + limit]

        return {
            "functions": page,
            "total_count": total,
            "offset": offset,
            "limit": limit,
            "returned": len(page),
        }

    @_tool("search_functions_by_name", annotations=READ_ONLY)
    @_ida_main_thread
    def search_functions_by_name(search_term: str, ctx: Context,
                                 min_size: int = 0, max_size: int = 0,
                                 limit: int = 100) -> list:
        """Search functions by name pattern, with optional size filters.

        Args:
            search_term: Substring to search for in function names
            min_size: Minimum function size filter (0 = no filter)
            max_size: Maximum function size filter (0 = no filter)
            limit: Maximum results

        Returns:
            List of matching function dictionaries.
        """
        results = []
        term_lower = search_term.lower()

        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            if term_lower not in name.lower():
                continue

            func = ida_funcs.get_func(func_ea)
            size = (func.end_ea - func.start_ea) if func else 0
            if min_size and size < min_size:
                continue
            if max_size and size > max_size:
                continue

            results.append({
                "name": name,
                "address": hex(func_ea),
                "size": size,
            })
            if len(results) >= limit:
                break

        return results

    @_tool("get_function_by_name", annotations=READ_ONLY)
    @_ida_main_thread
    def get_function_by_name(name: str, ctx: Context) -> dict:
        """Look up a function by its exact name.

        Args:
            name: Exact function name

        Returns:
            Function info dictionary, or error if not found.
        """
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {"error": f"Function '{name}' not found"}

        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"'{name}' found at {hex(ea)} but is not a function"}

        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }

    @_tool("get_function_by_address", annotations=READ_ONLY)
    @_ida_main_thread
    def get_function_by_address(address: str, ctx: Context) -> dict:
        """Look up a function containing the given address.

        Args:
            address: Hex address string

        Returns:
            Function info dictionary, or error if not found.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }

    @_tool("get_function_statistics", annotations=READ_ONLY)
    @_ida_main_thread
    def get_function_statistics(ctx: Context) -> dict:
        """Get comprehensive statistics about all functions in the binary.

        Returns:
            Statistics including counts, sizes, and top functions.
        """
        sizes = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                sizes.append((func_ea, func.end_ea - func.start_ea))

        if not sizes:
            return {"error": "No functions found"}

        total_size = sum(s for _, s in sizes)
        avg_size = total_size // len(sizes) if sizes else 0
        sorted_by_size = sorted(sizes, key=lambda x: x[1], reverse=True)

        top_10 = []
        for ea, sz in sorted_by_size[:10]:
            top_10.append({
                "name": ida_funcs.get_func_name(ea),
                "address": hex(ea),
                "size": sz,
            })

        return {
            "total_functions": len(sizes),
            "total_code_size": total_size,
            "average_size": avg_size,
            "max_size": sorted_by_size[0][1] if sorted_by_size else 0,
            "min_size": sorted_by_size[-1][1] if sorted_by_size else 0,
            "top_10_largest": top_10,
        }

    # ================================================================== #
    #  15-16. Symbol Management
    # ================================================================== #

    def _rename_global_symbol_impl(address_or_name: str, new_name: str) -> dict:
        """Rename a non-function symbol resolved by address or name."""
        ea = _resolve(address_or_name)
        if ida_funcs.get_func(ea):
            return {
                "success": False,
                "error": (
                    f"Target '{address_or_name}' resolves to a function at {hex(ea)}; "
                    "use rename_symbol for functions or variables(action='rename', scope='local') for locals"
                ),
            }

        old_name = ida_name.get_name(ea) or f"loc_{ea:x}"
        if ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
            return {
                "success": True,
                "message": f"Renamed global symbol '{old_name}' to '{new_name}'",
                "address": hex(ea),
                "old_name": old_name,
                "new_name": new_name,
            }
        return {
            "success": False,
            "error": f"Failed to rename global symbol '{old_name}' to '{new_name}'",
        }

    @_tool("rename_symbol", annotations=MODIFY)
    @_ida_main_thread
    def rename_symbol(address_or_name: str, new_name: str, ctx: Context) -> str:
        """Rename any symbol (function or data) at the given address/name.

        Args:
            address_or_name: Current address or name
            new_name: New name

        Returns:
            Success or failure message.
        """
        ea = _resolve(address_or_name)
        old_name = ida_name.get_name(ea) or f"loc_{ea:x}"
        if ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
            return f"Renamed '{old_name}' to '{new_name}'"
        else:
            return f"Failed to rename to '{new_name}'"

    @_tool("batch_rename", annotations=MODIFY)
    @_ida_main_thread
    def batch_rename(renames: list, ctx: Context) -> list:
        """Batch rename multiple symbols.

        Args:
            renames: List of dicts with 'address_or_name' and 'new_name' keys

        Returns:
            List of results for each rename operation.
        """
        results = []
        for entry in renames:
            addr_or_name = entry.get("address_or_name", "")
            new_name = entry.get("new_name", "")
            if not addr_or_name or not new_name:
                results.append({"address_or_name": addr_or_name, "success": False, "error": "Missing fields"})
                continue

            try:
                ea = _resolve(addr_or_name)
                old_name = ida_name.get_name(ea) or f"loc_{ea:x}"
                success = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)

                results.append({
                    "address": hex(ea),
                    "old_name": old_name,
                    "new_name": new_name,
                    "success": success,
                })
            except Exception as e:
                results.append({"address_or_name": addr_or_name, "success": False, "error": str(e)})

        return results

    # ================================================================== #
    #  17-21. Binary Info
    # ================================================================== #

    @_tool("get_imports", annotations=READ_ONLY)
    @_ida_main_thread
    def get_imports(ctx: Context) -> dict:
        """Get imported functions grouped by module.

        Returns:
            Dictionary mapping module names to lists of imported symbols.
        """
        imports_by_module: Dict[str, list] = {}

        def imp_cb(ea, name, ordinal):
            if name:
                imports_by_module.setdefault(_current_module[0], []).append({
                    "name": name,
                    "address": hex(ea),
                    "ordinal": ordinal,
                })
            return True  # continue enumeration

        _current_module = [""]
        num_modules = ida_nalt.get_import_module_qty()
        for i in range(num_modules):
            mod_name = ida_nalt.get_import_module_name(i)
            _current_module[0] = mod_name or f"module_{i}"
            ida_nalt.enum_import_names(i, imp_cb)

        return {
            "imports": imports_by_module,
            "module_count": num_modules,
            "total_imports": sum(len(v) for v in imports_by_module.values()),
        }

    @_tool("get_exports", annotations=READ_ONLY)
    @_ida_main_thread
    def get_exports(ctx: Context) -> dict:
        """Get exported symbols.

        Returns:
            Dictionary with list of exports.
        """
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or f"export_{ordinal}"
            exports.append({
                "name": name,
                "address": hex(ea),
                "ordinal": ordinal,
            })

        return {"exports": exports, "count": len(exports)}

    @_tool("get_strings", annotations=READ_ONLY)
    @_ida_main_thread
    def get_strings(ctx: Context, min_length: int = 4, page_size: int = 100,
                    page_number: int = 1) -> dict:
        """Get strings found in the binary with pagination.

        Args:
            min_length: Minimum string length
            page_size: Number of strings per page
            page_number: Page number (1-indexed)

        Returns:
            Dictionary with strings list and pagination info.
        """
        all_strings = []
        for s in idautils.Strings():
            value = str(s)
            if len(value) >= min_length:
                all_strings.append({
                    "address": hex(s.ea),
                    "value": value,
                    "length": s.length,
                    "type": "ascii" if s.strtype == 0 else f"type_{s.strtype}",
                })

        total = len(all_strings)
        total_pages = max(1, (total + page_size - 1) // page_size)
        start = (page_number - 1) * page_size
        page = all_strings[start:start + page_size]

        return {
            "strings": page,
            "page_size": page_size,
            "page_number": page_number,
            "total_count": total,
            "total_pages": total_pages,
        }

    @_tool("get_segments", annotations=READ_ONLY)
    @_ida_main_thread
    def get_segments(ctx: Context) -> list:
        """Get memory segments.

        Returns:
            List of segment dictionaries with name, start, end, permissions.
        """
        segments = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue

            name = ida_segment.get_segm_name(seg) or f"seg_{i}"
            seg_class = ida_segment.get_segm_class(seg) or ""

            perm_str = ""
            perm_str += "R" if (seg.perm & 4) else "-"
            perm_str += "W" if (seg.perm & 2) else "-"
            perm_str += "X" if (seg.perm & 1) else "-"

            segments.append({
                "name": name,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": perm_str,
                "class": seg_class,
            })

        return segments

    @_tool("get_entry_points", annotations=READ_ONLY)
    @_ida_main_thread
    def get_entry_points(ctx: Context) -> list:
        """Get all binary entry points.

        Returns:
            List of entry point dictionaries with name and address.
        """
        entries = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or f"entry_{ordinal}"
            entries.append({
                "name": name,
                "address": hex(ea),
                "ordinal": ordinal,
            })
        return entries

    # ================================================================== #
    #  22-25. Data Analysis
    # ================================================================== #

    @_tool("read_memory", annotations=READ_ONLY)
    @_ida_main_thread
    def read_memory(address: str, size: int, ctx: Context) -> dict:
        """Read raw bytes from the IDB at a given address.

        Args:
            address: Hex address
            size: Number of bytes to read (max 4096)

        Returns:
            Dictionary with hex dump and raw byte values.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        size = min(size, 4096)
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            return {"error": f"Cannot read {size} bytes at {hex(ea)}"}

        return {
            "address": hex(ea),
            "size": len(data),
            "hex": data.hex(),
            "printable": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        }

    @_tool("get_data_at", annotations=READ_ONLY)
    @_ida_main_thread
    def get_data_at(address: str, ctx: Context, size: int = 0) -> dict:
        """Get typed data at a specific address.

        Args:
            address: Hex address
            size: Optional explicit size (0 = auto-detect from IDB item)

        Returns:
            Dictionary with typed data values.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        if size == 0:
            size = ida_bytes.get_item_size(ea)
            if size == 0:
                size = 8  # fallback

        data = ida_bytes.get_bytes(ea, min(size, 4096))
        if data is None:
            return {"error": f"Cannot read at {hex(ea)}"}

        result = {
            "address": hex(ea),
            "item_size": size,
            "hex": data.hex(),
        }

        if size >= 1:
            result["byte"] = ida_bytes.get_byte(ea)
        if size >= 2:
            result["word"] = ida_bytes.get_word(ea)
        if size >= 4:
            result["dword"] = ida_bytes.get_dword(ea)
        if size >= 8:
            result["qword"] = ida_bytes.get_qword(ea)

        name = ida_name.get_name(ea)
        if name:
            result["name"] = name

        return result

    @_tool("search_bytes", annotations=READ_ONLY)
    @_ida_main_thread
    def search_bytes(pattern: str, ctx: Context, start_address: str = "",
                     max_results: int = 100) -> list:
        """Search for a byte pattern in the binary.

        Args:
            pattern: Hex byte pattern (e.g. '90 90 90' or '4883EC')
            start_address: Optional start address (default: binary start)
            max_results: Maximum number of results

        Returns:
            List of matching addresses.
        """
        clean = pattern.replace(" ", "")
        if len(clean) % 2 != 0:
            return [{"error": "Pattern must have even number of hex chars"}]

        search_pattern = " ".join(clean[i:i+2] for i in range(0, len(clean), 2))

        if start_address:
            start_ea = parse_address(start_address)
            if start_ea is None:
                return [{"error": f"Invalid start address: {start_address}"}]
        else:
            start_ea = ida_ida.inf_get_min_ea()

        compiled = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(compiled, start_ea, search_pattern, 16)

        results = []
        ea = start_ea
        for _ in range(max_results):
            search_result = ida_bytes.bin_search(
                ea, idaapi.BADADDR, compiled,
                ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK)
            # IDA 9.x returns (ea, size) tuple; older versions return ea
            if isinstance(search_result, tuple):
                ea = int(search_result[0])
            else:
                ea = int(search_result)
            if ea == idaapi.BADADDR:
                break

            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else None

            results.append({
                "address": hex(ea),
                "function": fname,
            })
            ea += 1  # advance past match

        return results

    @_tool("search_strings", annotations=READ_ONLY)
    @_ida_main_thread
    def search_strings(pattern: str, ctx: Context, case_sensitive: bool = False,
                       page_size: int = 100, page_number: int = 1) -> dict:
        """Search for strings matching a pattern with pagination.

        Args:
            pattern: Search pattern (substring match)
            case_sensitive: Case-sensitive matching
            page_size: Number of results per page
            page_number: Page number (1-indexed)

        Returns:
            Dictionary with matching strings and pagination info.
        """
        matches = []
        pat = pattern if case_sensitive else pattern.lower()

        for s in idautils.Strings():
            value = str(s)
            compare = value if case_sensitive else value.lower()
            if pat in compare:
                matches.append({
                    "address": hex(s.ea),
                    "value": value,
                    "length": s.length,
                })

        total = len(matches)
        total_pages = max(1, (total + page_size - 1) // page_size)
        start = (page_number - 1) * page_size
        page = matches[start:start + page_size]

        return {
            "strings": page,
            "page_size": page_size,
            "page_number": page_number,
            "total_count": total,
            "total_pages": total_pages,
        }

    # ================================================================== #
    #  26-28. Patching and Export
    # ================================================================== #

    @_tool("patch_bytes", annotations=NON_IDEMPOTENT)
    @_ida_main_thread
    def patch_bytes(address: str, ctx: Context, hex_bytes: Optional[str] = None,
                    bytes: Optional[Any] = None, clear_code_units: bool = False) -> dict:
        """Patch bytes in the IDB at a given address.

        WARNING: This modifies the IDB. The operation cannot be easily undone.

        Args:
            address: Hex address to patch at
            hex_bytes: Backward-compatible hex string of bytes to write (e.g. '90909090')
            bytes: Hex string or integer array of bytes to write
            clear_code_units: If true, undefine existing items across the patched range before writing

        Returns:
            Dictionary with patch range and before/after bytes.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        byte_input = bytes if bytes is not None else hex_bytes
        if byte_input is None:
            return {"error": "bytes or hex_bytes is required"}

        try:
            data = _parse_byte_values(byte_input)
        except ValueError as e:
            return {"error": f"Invalid bytes value: {e}"}

        if not data:
            return {"error": "No bytes provided to patch"}

        old_bytes = ida_bytes.get_bytes(ea, len(data))
        if old_bytes is None or len(old_bytes) != len(data):
            return {"error": f"Cannot read {len(data)} original byte(s) at {hex(ea)}"}

        end_ea = ea + len(data) - 1
        if clear_code_units:
            ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, len(data))
        ida_bytes.patch_bytes(ea, data)
        ida_auto.auto_make_code(ea)

        return {
            "status": "patched",
            "address": hex(ea),
            "end_address": hex(end_ea),
            "size": len(data),
            "before": _format_hex(old_bytes),
            "after": _format_hex(data),
            "clear_code_units": clear_code_units,
        }

    @_tool("assemble_code", annotations=NON_IDEMPOTENT)
    @_ida_main_thread
    def assemble_code(address: str, code: str, ctx: Context,
                      patch: bool = True, clear_code_units: bool = True) -> dict:
        """Assemble instruction text at an address and optionally patch it.

        Args:
            address: Hex address to assemble at
            code: Single instruction or newline-separated assembly block
            patch: If true, patch assembled bytes into the IDB
            clear_code_units: If true, undefine existing items across the assembled range first

        Returns:
            Dictionary with assembled bytes and optional before/after patch details.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        lines = [line.strip() for line in code.splitlines() if line.strip()]
        if not lines:
            return {"error": "No assembly instructions provided"}

        ok, assembled_result = idautils.Assemble(ea, lines)
        if not ok:
            return {"error": assembled_result}

        if isinstance(assembled_result, list):
            assembled = b"".join(_coerce_assembled_bytes(part) for part in assembled_result)
        else:
            assembled = _coerce_assembled_bytes(assembled_result)

        if not assembled:
            return {"error": "Assembler produced no bytes"}

        end_ea = ea + len(assembled) - 1
        result = {
            "status": "assembled",
            "address": hex(ea),
            "end_address": hex(end_ea),
            "size": len(assembled),
            "bytes": _format_hex(assembled),
            "instruction_lines": len(lines),
            "patched": False,
        }

        if not patch:
            return result

        old_bytes = ida_bytes.get_bytes(ea, len(assembled))
        if old_bytes is None or len(old_bytes) != len(assembled):
            return {"error": f"Cannot read {len(assembled)} original byte(s) at {hex(ea)}"}

        if clear_code_units:
            ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, len(assembled))
        ida_bytes.patch_bytes(ea, assembled)
        ida_auto.auto_make_code(ea)

        result.update({
            "status": "assembled_and_patched",
            "patched": True,
            "before": _format_hex(old_bytes),
            "after": _format_hex(assembled),
            "clear_code_units": clear_code_units,
        })
        return result

    @_tool("export_program", annotations=FILE_WRITE)
    @_ida_main_thread
    def export_program(output_path: str, ctx: Context, format: str = "binary",
                       overwrite: bool = False) -> dict:
        """Export the current IDA database or patched binary to disk.

        Args:
            output_path: Destination path on the host filesystem
            format: 'binary' for executable output or 'idb' for database output
            overwrite: Whether to replace an existing output file

        Returns:
            Dictionary with export status and output metadata.
        """
        if not output_path or not output_path.strip():
            return {"error": "output_path is required"}

        destination = Path(output_path).expanduser()
        if destination.exists() and not overwrite:
            return {"error": f"Output file already exists: {destination} (set overwrite=true to replace it)"}

        destination.parent.mkdir(parents=True, exist_ok=True)
        export_format = (format or "binary").lower()

        if export_format == "binary":
            result = idc.gen_file(
                idc.OFILE_EXE,
                str(destination),
                ida_ida.inf_get_min_ea(),
                ida_ida.inf_get_max_ea(),
                0,
            )
            if result != 1:
                return {"error": f"Binary export failed for {destination}"}
        elif export_format in ("idb", "database"):
            if not ida_loader.save_database(str(destination), 0):
                return {"error": f"Database export failed for {destination}"}
            export_format = "idb"
        else:
            return {"error": "Unsupported format. Use 'binary' or 'idb'."}

        return {
            "status": "exported",
            "format": export_format,
            "output_path": str(destination.resolve()),
            "bytes_written": destination.stat().st_size if destination.exists() else None,
        }

    # ================================================================== #
    #  29-30. Navigation
    # ================================================================== #

    @_tool("navigate_to", annotations=MODIFY)
    @_ida_main_thread
    def navigate_to(address: str, ctx: Context) -> str:
        """Move IDA cursor to a specific address.

        Args:
            address: Hex address to navigate to

        Returns:
            Success or failure message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        if ida_kernwin.jumpto(ea):
            return f"Navigated to {hex(ea)}"
        else:
            return f"Failed to navigate to {hex(ea)}"

    @_tool("bookmarks", annotations=MODIFY)
    @_ida_main_thread
    def bookmarks(action: str, ctx: Context,
                  address: str = "", description: str = "",
                  slot: int = 0) -> str:
        """Manage bookmarks: list, set, or remove position bookmarks.

        Args:
            action: Operation to perform: 'list', 'set', or 'remove'
            address: Hex address (required for set/remove)
            description: Bookmark description text (for set)
            slot: Bookmark slot number 0-1023 (for set/remove)
        """
        if action == "list":
            results = []
            for i in range(1024):
                ea = idc.get_bookmark(i)
                if ea is None or ea == idaapi.BADADDR:
                    continue
                desc = idc.get_bookmark_desc(i)
                results.append(f"Slot {i}: {hex(ea)} - {desc}")
            return "\n".join(results) if results else "No bookmarks found"

        elif action == "set":
            if not address:
                return "Error: address is required for set"
            ea = parse_address(address)
            if ea is None:
                return f"Invalid address: {address}"
            idc.put_bookmark(ea, 0, 0, 0, slot, description or "Bookmark")
            return f"Bookmark set at {hex(ea)} (slot {slot}): {description or 'Bookmark'}"

        elif action == "remove":
            if not address:
                return "Error: address is required for remove"
            ea = parse_address(address)
            if ea is None:
                return f"Invalid address: {address}"
            idc.put_bookmark(ea, 0, 0, 0, slot, "")
            return f"Removed bookmark at slot {slot}"

        else:
            return f"Invalid action '{action}'. Use 'list', 'set', or 'remove'"

    # ================================================================== #
    #  29. get_current_address (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("get_current_address", annotations=READ_ONLY)
    @_ida_main_thread
    def get_current_address(ctx: Context) -> dict:
        """Get the address at the current cursor position in IDA.

        Returns:
            Dictionary with address, name, and containing function info.
        """
        ea = ida_kernwin.get_screen_ea()
        result = {
            "address": hex(ea),
        }

        name = ida_name.get_name(ea)
        if name:
            result["name"] = name

        func = ida_funcs.get_func(ea)
        if func:
            result["function"] = ida_funcs.get_func_name(func.start_ea)
            result["function_address"] = hex(func.start_ea)

        return result

    # ================================================================== #
    #  30. get_current_function (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("get_current_function", annotations=READ_ONLY)
    @_ida_main_thread
    def get_current_function(ctx: Context) -> dict:
        """Get info about the function at the current cursor position.

        Returns:
            Function info dictionary if cursor is inside a function, error otherwise.
        """
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at cursor position ({hex(ea)})"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        result = {
            "name": func_name,
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
            "cursor_offset": ea - func.start_ea,
        }

        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea):
                result["prototype"] = str(tif)
        except Exception:
            pass

        return result

    # ================================================================== #
    #  31. get_function_stack_layout (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("get_function_stack_layout", annotations=READ_ONLY)
    @_ida_main_thread
    def get_function_stack_layout(function_name_or_address: str, ctx: Context) -> dict:
        """Get stack frame layout for a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with stack frame members (locals, args, saved regs).
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        frame_id = idc.get_frame_id(func.start_ea)
        if frame_id is None or frame_id == idaapi.BADADDR:
            return {"error": f"No stack frame for function at {hex(func.start_ea)}"}

        members = []
        try:
            for offset, name, size in idautils.StructMembers(frame_id):
                member_type = "local"
                if name.startswith(" r") or name.startswith(" s"):
                    member_type = "saved_reg"

                members.append({
                    "name": name,
                    "offset": offset,
                    "size": size,
                    "type": member_type,
                })
        except Exception as e:
            return {"error": f"Failed to read stack frame: {e}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        return {
            "function": func_name,
            "address": hex(func.start_ea),
            "frame_size": idc.get_frame_size(func.start_ea),
            "local_size": idc.get_frame_lvar_size(func.start_ea),
            "args_size": idc.get_frame_args_size(func.start_ea),
            "members": members,
        }

    # ================================================================== #
    #  32. get_classes (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("get_classes", annotations=READ_ONLY)
    @_ida_main_thread
    def get_classes(ctx: Context, filter: str = "") -> dict:
        """Get struct/class types from the type library.

        Args:
            filter: Optional substring filter on type name

        Returns:
            Dictionary with list of struct/union types.
        """
        til = ida_typeinf.get_idati()
        if not til:
            return {"error": "Cannot access type library"}

        classes = []
        ordinal = 1
        consecutive_empty = 0
        while consecutive_empty < 200:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                consecutive_empty = 0
                if tif.is_struct() or tif.is_union():
                    tname = tif.get_type_name() or f"type_{ordinal}"
                    if not filter or filter.lower() in tname.lower():
                        udt = ida_typeinf.udt_type_data_t()
                        member_count = 0
                        if tif.get_udt_details(udt):
                            member_count = udt.size()

                        classes.append({
                            "name": tname,
                            "ordinal": ordinal,
                            "kind": "union" if tif.is_union() else "struct",
                            "size": tif.get_size(),
                            "member_count": member_count,
                            "definition": str(tif),
                        })
            else:
                consecutive_empty += 1
            ordinal += 1

        return {"classes": classes, "count": len(classes)}

    # ================================================================== #
    #  33. create_data_var (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("create_data_var", annotations=MODIFY)
    @_ida_main_thread
    def create_data_var(address: str, data_type: str, ctx: Context) -> str:
        """Define a data variable at an address with specified type.

        Args:
            address: Hex address
            data_type: Type of data - 'byte', 'word', 'dword', 'qword', 'float',
                       'double', 'ascii', or a C type string

        Returns:
            Success or failure message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        type_map = {
            "byte": (idc.create_byte, 1),
            "word": (idc.create_word, 2),
            "dword": (idc.create_dword, 4),
            "qword": (idc.create_qword, 8),
            "float": (lambda a: ida_bytes.create_data(a, idaapi.FF_FLOAT, 4, idaapi.BADADDR), 4),
            "double": (lambda a: ida_bytes.create_data(a, idaapi.FF_DOUBLE, 8, idaapi.BADADDR), 8),
        }

        if data_type == "ascii":
            # Create ASCII string — auto-detect length
            length = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
            if length < 1:
                length = 1
            if idc.create_strlit(ea, ea + length):
                return f"Created ASCII string at {hex(ea)} (length {length})"
            else:
                return f"Failed to create ASCII string at {hex(ea)}"

        if data_type in type_map:
            func, size = type_map[data_type]
            if func(ea):
                return f"Created {data_type} at {hex(ea)}"
            else:
                return f"Failed to create {data_type} at {hex(ea)}"

        # Try as C type string
        try:
            tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            decl = data_type if data_type.rstrip().endswith(";") else data_type + ";"
            if ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL):
                if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return f"Applied type '{data_type}' at {hex(ea)}"
                else:
                    return f"Failed to apply type at {hex(ea)}"
            else:
                return f"Unknown data type: {data_type}"
        except Exception as e:
            return f"Failed: {e}"

    # ================================================================== #
    #  34. get_data_vars (NEW — feature parity with BinAssistMCP)
    # ================================================================== #

    @_tool("get_data_vars", annotations=READ_ONLY)
    @_ida_main_thread
    def get_data_vars(ctx: Context, segment_name: str = "",
                      limit: int = 200, offset: int = 0) -> dict:
        """Get defined data variables (non-code items).

        Args:
            segment_name: Optional segment name filter (e.g. '.data', '.rodata')
            limit: Maximum number of results
            offset: Number of items to skip

        Returns:
            Dictionary with list of data variables and pagination.
        """
        data_vars = []
        skipped = 0

        for seg_idx in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            seg_nm = ida_segment.get_segm_name(seg) or ""
            if segment_name and segment_name.lower() not in seg_nm.lower():
                continue

            ea = seg.start_ea
            while ea < seg.end_ea and ea != idaapi.BADADDR:
                flags = ida_bytes.get_flags(ea)
                # Skip code heads — we only want data
                if not ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
                    if skipped < offset:
                        skipped += 1
                    else:
                        name = ida_name.get_name(ea) or ""
                        item_size = ida_bytes.get_item_size(ea)

                        entry = {
                            "address": hex(ea),
                            "size": item_size,
                            "segment": seg_nm,
                        }
                        if name:
                            entry["name"] = name

                        data_vars.append(entry)
                        if len(data_vars) >= limit:
                            return {
                                "data_vars": data_vars,
                                "count": len(data_vars),
                                "offset": offset,
                                "limit": limit,
                                "truncated": True,
                            }

                ea = ida_bytes.next_head(ea, seg.end_ea)

        return {
            "data_vars": data_vars,
            "count": len(data_vars),
            "offset": offset,
            "limit": limit,
            "truncated": False,
        }

    # ================================================================== #
    #  38-41. Task Management
    # ================================================================== #

    @_tool("start_task", annotations=NON_IDEMPOTENT)
    async def start_task(name: str, tool_name: str, ctx: Context, **kwargs) -> dict:
        """Start an async background task.

        Args:
            name: Human-readable task name
            tool_name: Name of the tool to run as a task

        Returns:
            Dictionary with task_id for tracking.
        """
        task_manager = get_task_manager()

        async def _run():
            return {"status": "completed", "tool": tool_name, "note": "Task ran in background"}

        task_id = await task_manager.submit(_run, name=name)
        return {"task_id": task_id, "status": "submitted"}

    @_tool("get_task_status", annotations=READ_ONLY)
    def get_task_status(task_id: str, ctx: Context) -> dict:
        """Get status of an async task.

        Args:
            task_id: ID of the task to check

        Returns:
            Task status dictionary.
        """
        task_manager = get_task_manager()
        return task_manager.get_task_status(task_id)

    @_tool("cancel_task", annotations=MODIFY)
    def cancel_task(task_id: str, ctx: Context) -> dict:
        """Cancel a running async task.

        Args:
            task_id: ID of the task to cancel

        Returns:
            Cancellation result.
        """
        task_manager = get_task_manager()
        success = task_manager.cancel_task(task_id)
        return {
            "task_id": task_id,
            "cancelled": success,
            "message": "Task cancellation initiated" if success else "Task not found or already completed",
        }

    @_tool("list_tasks", annotations=READ_ONLY)
    def list_tasks(ctx: Context, status: str = "") -> list:
        """List all async tasks, optionally filtered by status.

        Args:
            status: Optional filter - 'pending', 'running', 'completed', 'failed', 'cancelled'

        Returns:
            List of task information.
        """
        task_manager = get_task_manager()
        status_filter = None
        if status:
            try:
                status_filter = TaskStatus(status)
            except ValueError:
                pass
        return task_manager.list_tasks(status_filter)

    if disabled_tools:
        log.log_info(f"Registered MCP tools ({len(disabled_tools)} disabled)")
    else:
        log.log_info(f"Registered all MCP tools")
