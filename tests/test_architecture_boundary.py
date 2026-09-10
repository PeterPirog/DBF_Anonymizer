"""P0 architecture-boundary regression evidence for REQ-P0-001/REQ-P0-002.

Static (AST-based) checks that fail if the active ``src/dbf_anonymizer``
production code reintroduces the superseded 0.3 DBF/FPT paths or leaves the
public dependency boundary.

Allowed (the legitimate public dbfbridge namespace):

    import dbfbridge
    dbfbridge.inspect_table(path)
    import dbfbridge as bridge
    bridge.write_table(...)
    from dbfbridge import inspect_table, read_schema, iter_records
    from dbfbridge import iter_raw_records, write_table

Rejected (among others):

    import dbf_bridge
    from dbf_bridge import export_dbf
    import dbfbridge.core
    from dbfbridge.write import write_table
    from dbfbridge import _LAZY_SYMBOLS
    dbfbridge.write.write_table(...)
    import dbf / from dbf import Table
    export_dbf(...) / reconstruct_dbf(...)
    in-place binary DBF patching (open(..., "r+b")) and the historical raw
    DBF byte-patching/reconstruction path

The guard enforces the DBF/FPT ownership boundary only; it deliberately does
not ban generic implementation style (for example Python's ``struct``
module) for unrelated future uses.

The guard self-tests below feed representative allowed and forbidden
snippets through the same checker so a future refactor cannot accidentally
redefine the architecture boundary.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"
WORKFLOW_FILE = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "p0-package-boundary.yml"
)

#: Superseded 0.3 module-layout names tied to the raw patch / JSONL pipeline.
FORBIDDEN_MODULE_NAMES = (
    "rawpatch.py",
    "layout.py",
    "tableio.py",
    "jsonstream.py",
    "dictionary.py",
    "global_store.py",
)

#: Obsolete 0.3 pipeline operations — never production symbols.
FORBIDDEN_OPERATION_SYMBOLS = frozenset({"export_dbf", "reconstruct_dbf"})

#: The raw-record restoration sentinel of the 0.3 raw-patch path.
RAW_RECORD_SENTINEL = "__dbfbridge_raw_record__"

DBF_ARTIFACT_RE = re.compile(r"\.dbf\b|\.fpt\b|\.cdx\b|header_length|record_length", re.IGNORECASE)


class BoundaryViolation(AssertionError):
    """A production source violates the DBF/FPT dependency boundary."""


# ---------------------------------------------------------------------------
# AST guard core (shared by the production scan and the self-tests)
# ---------------------------------------------------------------------------


def _import_targets(node: ast.Import | ast.ImportFrom) -> list[tuple[str, str]]:
    """Return (imported_module, bound_name) pairs for an import statement.

    ``import X``          -> (X, X)
    ``import X as Y``     -> (X, Y)
    ``from X import a``   -> (X, a)
    ``from X import a as Y`` -> (X, Y)
    """
    if isinstance(node, ast.Import):
        return [(alias.name, alias.asname or alias.name) for alias in node.names]
    module = node.module or ""
    targets = []
    for alias in node.names:
        name = alias.name if node.module else f"{(node.level or 0)}.{alias.name}"
        targets.append((name, alias.asname or alias.name.split(".")[0]))
    return targets


def _import_full_name(node: ast.ImportFrom) -> str:
    """Full dotted module of a ``from ... import`` node (``.``-relative included)."""
    prefix = "." * (node.level or 0)
    return f"{prefix}{node.module or ''}"


def _is_dbf_engine_module(name: str) -> bool:
    return name == "dbf" or name.startswith("dbf.")


def _is_dbf_bridge_module(name: str) -> bool:
    return name == "dbf_bridge" or name.startswith("dbf_bridge.")


def _dbfbridge_aliases(tree: ast.Module) -> set[str]:
    """Binding names that reference the public ``dbfbridge`` namespace."""
    aliases: set[str] = {"dbfbridge"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "dbfbridge":
                    aliases.add(alias.asname or "dbfbridge")
    return aliases


def _is_private_dbfbridge_internal(symbol: str) -> bool:
    """Decide whether *symbol* is a private dbfbridge internal, not a public name.

    The published ``dbfbridge`` facade is a single module delegating lazily to
    the historical ``dbf_bridge`` package, so a symbol is a private internal
    exactly when it is an underscore name (non-dunder) or resolves as a
    physical ``dbf_bridge`` submodule through the real installed
    distribution.  Public names such as ``inspect_table`` or ``__version__``
    never resolve as submodules.
    """
    if symbol.startswith("_") and not (symbol.startswith("__") and symbol.endswith("__")):
        return True
    try:
        return importlib.util.find_spec(f"dbf_bridge.{symbol}") is not None
    except (ImportError, ValueError):
        return False


def _check_imports(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for module, bound in _import_targets(node):
                if _is_dbf_bridge_module(module):
                    raise BoundaryViolation(
                        f"import of the historical dbf_bridge namespace: {module!r}"
                    )
                if _is_dbf_engine_module(module):
                    raise BoundaryViolation(
                        f"direct use of the dbf library as DBF/FPT engine: import {module}"
                    )
                if module.startswith("dbfbridge."):
                    raise BoundaryViolation(
                        f"import of a dbfbridge private internal submodule: {module!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            full = _import_full_name(node)
            if _is_dbf_bridge_module(full):
                raise BoundaryViolation(
                    f"import of the historical dbf_bridge namespace: from {full} import ..."
                )
            if _is_dbf_engine_module(full):
                raise BoundaryViolation(
                    f"direct use of the dbf library as DBF/FPT engine: from {full} import ..."
                )
            if full == "dbfbridge":
                for module, bound in _import_targets(node):
                    symbol = module.rsplit(".", 1)[-1]
                    if symbol in FORBIDDEN_OPERATION_SYMBOLS:
                        raise BoundaryViolation(
                            f"obsolete 0.3 JSONL pipeline operation imported: {symbol!r}"
                        )
                    if _is_private_dbfbridge_internal(symbol):
                        raise BoundaryViolation(
                            f"private dbfbridge internal imported from the public "
                            f"namespace: {symbol!r}"
                        )
            elif full.startswith("dbfbridge."):
                raise BoundaryViolation(
                    f"import of a dbfbridge private internal submodule: from {full} import ..."
                )


def _base_attribute_chain(node: ast.Attribute) -> tuple[ast.Name, list[str]] | None:
    """Flatten ``a.b.c`` into (base Name node, [attr, ...]) when the base is a name."""
    attrs: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        attrs.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        return current, list(reversed(attrs))
    return None


def _check_names_and_attributes(tree: ast.Module) -> None:
    aliases = _dbfbridge_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_OPERATION_SYMBOLS:
            raise BoundaryViolation(
                f"obsolete 0.3 JSONL pipeline operation referenced: {node.id!r}"
            )
        if isinstance(node, ast.Attribute):
            base_chain = _base_attribute_chain(node)
            if base_chain is None:
                continue
            base, attrs = base_chain
            if base.id in aliases and attrs:
                first = attrs[0]
                if _is_private_dbfbridge_internal(first):
                    raise BoundaryViolation(
                        f"private dbfbridge internal referenced: dbfbridge.{first}"
                    )


def _open_modes(call: ast.Call) -> str:
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        return str(call.args[1].value)
    return ""


def _is_open_call(call: ast.Call) -> bool:
    func = call.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    return name == "open"


def _check_calls(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_open_call(node):
            mode = _open_modes(node).replace(" ", "")
            # Any binary read-write/update mode ("r+b", "rb+", "w+b", ...) is
            # the in-place byte-patching signature of the historical raw DBF
            # patch path.
            if "b" in mode and "+" in mode:
                raise BoundaryViolation(
                    f"in-place binary byte patching (mode {mode!r}) — the "
                    "historical raw DBF patch path writes DBF bytes in place; "
                    "1.0 delegates all DBF/FPT writing to public dbfbridge"
                )


def check_module(label: str, source: str) -> None:
    """Apply all source-level boundary rules to one module's source text."""
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        raise BoundaryViolation(f"{label}: source does not parse: {exc}") from exc
    _check_imports(tree)
    _check_names_and_attributes(tree)
    _check_calls(tree)
    if RAW_RECORD_SENTINEL in source:
        raise BoundaryViolation(
            f"{label}: raw-record restoration sentinel {RAW_RECORD_SENTINEL!r} present"
        )
    if re.search(r"struct\.(?:un)?pack", source) and DBF_ARTIFACT_RE.search(source):
        raise BoundaryViolation(
            f"{label}: struct-based DBF/FPT byte surgery outside the dbfbridge boundary"
        )


def check_module_file(path: Path) -> None:
    check_module(path.name, path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# production scan
# ---------------------------------------------------------------------------


def _production_sources() -> list[Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def test_production_sources_exist() -> None:
    assert _production_sources(), "the active package tree is missing"


def test_no_superseded_pipeline_modules() -> None:
    present = {path.name for path in _production_sources()}
    offending = present & set(FORBIDDEN_MODULE_NAMES)
    assert not offending, f"superseded 0.3 pipeline modules present: {sorted(offending)}"


def test_production_sources_respect_the_dbf_fpt_boundary() -> None:
    for path in _production_sources():
        check_module(str(path.relative_to(SRC_ROOT)), path.read_text(encoding="utf-8"))


def test_p0_acceptance_pin_is_wired_into_the_ci_gate() -> None:
    workflow = WORKFLOW_FILE.read_text(encoding="utf-8")
    assert "requirements/p0-dbfbridge-tested.txt" in workflow
    assert "--no-deps" in workflow
    assert "pip check" in workflow


# ---------------------------------------------------------------------------
# guard self-tests: allowed public forms
# ---------------------------------------------------------------------------


def _assert_allowed(source: str) -> None:
    check_module("<snippet>", source)


def _assert_forbidden(source: str, match: str) -> None:
    with pytest.raises(BoundaryViolation, match=match):
        check_module("<snippet>", source)


def test_guard_allows_plain_public_namespace_usage() -> None:
    _assert_allowed(
        "import dbfbridge\n\n"
        "def run(path):\n"
        "    info = dbfbridge.inspect_table(path)\n"
        "    schema = dbfbridge.read_schema(path)\n"
        "    for record in dbfbridge.iter_records(path):\n"
        "        yield record\n"
    )


def test_guard_allows_aliased_public_namespace_usage() -> None:
    _assert_allowed(
        "import dbfbridge as bridge\n\n"
        "def write(destination, schema, records):\n"
        "    return bridge.write_table(destination, schema=schema, records=records)\n"
    )


def test_guard_allows_from_import_of_public_symbols() -> None:
    _assert_allowed(
        "from dbfbridge import (\n"
        "    inspect_table,\n"
        "    read_schema,\n"
        "    iter_records,\n"
        "    iter_raw_records,\n"
        "    write_table,\n"
        ")\n"
    )


def test_guard_allows_public_dunder_version_access() -> None:
    _assert_allowed("import dbfbridge\n\nversion = dbfbridge.__version__\n")


# ---------------------------------------------------------------------------
# guard self-tests: forbidden forms
# ---------------------------------------------------------------------------


def test_guard_rejects_historical_dbf_bridge_namespace() -> None:
    _assert_forbidden("import dbf_bridge\n", r"historical dbf_bridge namespace")
    _assert_forbidden("from dbf_bridge import export_dbf\n", r"historical dbf_bridge namespace")
    _assert_forbidden("import dbf_bridge.core as core\n", r"historical dbf_bridge namespace")


def test_guard_rejects_dbfbridge_private_submodule_imports() -> None:
    _assert_forbidden("import dbfbridge.core\n", r"private internal submodule")
    _assert_forbidden("from dbfbridge.write import write_table\n", r"private internal submodule")
    _assert_forbidden("import dbfbridge.core.records as records\n", r"private internal submodule")


def test_guard_rejects_dbfbridge_private_symbol_imports() -> None:
    _assert_forbidden(
        "from dbfbridge import _LAZY_SYMBOLS\n", r"private dbfbridge internal"
    )
    _assert_forbidden(
        "from dbfbridge import core\n", r"private dbfbridge internal imported"
    )


def test_guard_rejects_dbfbridge_private_submodule_references() -> None:
    _assert_forbidden(
        "import dbfbridge\n\n"
        "def write(destination, schema, records):\n"
        "    return dbfbridge.write.write_table(destination, schema=schema, records=records)\n",
        r"private dbfbridge internal referenced",
    )
    _assert_forbidden(
        "import dbfbridge\n\nsymbols = dbfbridge._LAZY_SYMBOLS\n",
        r"private dbfbridge internal referenced",
    )


def test_guard_rejects_direct_dbf_engine_use() -> None:
    _assert_forbidden("import dbf\n", r"direct use of the dbf library")
    _assert_forbidden("from dbf import Table\n", r"direct use of the dbf library")
    _assert_forbidden("import dbf.tables as tables\n", r"direct use of the dbf library")


def test_guard_rejects_obsolete_export_reconstruct_pipeline() -> None:
    _assert_forbidden(
        "from dbfbridge import export_dbf\n", r"obsolete 0\.3 JSONL pipeline operation"
    )
    _assert_forbidden(
        "def convert(source, output):\n"
        "    reconstruct_dbf(source, output)\n",
        r"obsolete 0\.3 JSONL pipeline operation",
    )
    _assert_forbidden(
        "import dbf_bridge\n\nexport_dbf(source, output)\n",
        r"historical dbf_bridge namespace",
    )


def test_guard_rejects_in_place_binary_dbf_patching() -> None:
    _assert_forbidden(
        "def patch(path):\n"
        "    with open(path, 'r+b') as handle:\n"
        "        handle.write(b'x')\n",
        r"in-place binary byte patching",
    )
    _assert_forbidden(
        "def patch(path):\n"
        "    with open(path, mode='rb+') as handle:\n"
        "        handle.write(b'x')\n",
        r"in-place binary byte patching",
    )


def test_guard_rejects_raw_record_restoration_sentinel() -> None:
    _assert_forbidden(
        "RAW_KEY = '__dbfbridge_raw_record__'\n", r"raw-record restoration sentinel"
    )


def test_guard_rejects_struct_based_dbf_byte_surgery() -> None:
    _assert_forbidden(
        "import struct\n\n"
        "HEADER_LENGTH = 32\n"
        "def parse(data):\n"
        "    return struct.unpack('<B', data[:1])\n",
        r"struct-based DBF/FPT byte surgery",
    )


def test_guard_allows_struct_and_r_plus_b_for_unrelated_future_uses() -> None:
    # struct without DBF artifact references in the same module is allowed.
    _assert_allowed(
        "import struct\n\n"
        "def encode(value):\n"
        "    return struct.pack('<i', value)\n"
    )
    # A text-mode reopen (no 'b') is not the raw-DBF patch path.
    _assert_allowed(
        "def append_log(path, line):\n"
        "    with open(path, 'a') as handle:\n"
        "        handle.write(line)\n"
    )