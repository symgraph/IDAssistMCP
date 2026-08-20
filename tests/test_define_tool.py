import unittest
from types import SimpleNamespace

from idassist_mcp import tools


class _Mcp:
    def __init__(self):
        self.tools = {}

    def tool(self, **_kwargs):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register


class _Bytes:
    DELIT_SIMPLE = 0
    DELIT_EXPAND = 1

    def __init__(self):
        self.calls = []

    def get_item_size(self, _ea):
        return 1

    def del_items(self, ea, flags, count):
        self.calls.append((ea, flags, count))
        return True


class _Funcs:
    def __init__(self):
        self.deleted = []

    def del_func(self, ea):
        self.deleted.append(ea)
        return True


class _Ua:
    def __init__(self, lengths):
        self.lengths = lengths
        self.created = []

    @staticmethod
    def insn_t():
        return object()

    def decode_insn(self, _insn, ea):
        return self.lengths.get(ea, 0)

    def create_insn(self, ea):
        self.created.append(ea)
        return self.lengths.get(ea, 0)


class DefineToolTests(unittest.TestCase):
    def setUp(self):
        self.mcp = _Mcp()
        self.bytes = _Bytes()
        self.funcs = _Funcs()
        tools.idaapi = SimpleNamespace(BADADDR=-1)
        tools.ida_bytes = self.bytes
        tools.ida_funcs = self.funcs
        tools.ida_ua = _Ua({0x3000: 2})
        tools.register_tools(self.mcp)
        self.define = self.mcp.tools["define"]

    def test_undefine_preserves_functions(self):
        result = self.define("undefine", "0x1000", None)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.funcs.deleted, [])

    def test_explicit_undefine_range_does_not_expand(self):
        result = self.define("undefine", "0x2000", None, size=4)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.bytes.calls, [(0x2000, _Bytes.DELIT_SIMPLE, 4)])

    def test_code_range_is_checked_before_modification(self):
        result = self.define("code", "0x3000", None, size=1)

        self.assertIn("error", result)
        self.assertEqual(tools.ida_ua.created, [])


if __name__ == "__main__":
    unittest.main()
