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
    in-place binary patching of DBF/FPT artifacts (open(..., "r+b") on a
    .dbf/.fpt/.cdx target or with DBF/FPT layout context in the module) and
    the historical raw DBF byte-patching/reconstruction path

The guard enforces the DBF/FPT ownership boundary only; it deliberately does
not ban generic implementation style (for example Python's ``struct`` module
or binary update I/O on unrelated artifacts) for unrelated future uses.

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


def _dbf_artifact_path_argument(call: ast.Call) -> str | None:
    """Statically visible literal path of an ``open()`` call, if any."""
    if call.args and isinstance(call.args[0], ast.Constant):
        value = call.args[0].value
        if isinstance(value, bytes):
            return value.decode("latin-1")
        if isinstance(value, str):
            return value
    return None


def _check_calls(tree: ast.Module, source: str) -> None:
    # Module-level DBF/FPT context (artifact names, header/record-length
    # surgery or the raw-record sentinel) turns a binary update open into
    # evidence of the historical raw DBF patch path.  Without that context a
    # binary update open on an unrelated artifact stays allowed.
    module_has_dbf_context = bool(
        DBF_ARTIFACT_RE.search(source) or RAW_RECORD_SENTINEL in source
    )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_open_call(node):
            continue
        mode = _open_modes(node).replace(" ", "")
        if not ("b" in mode and "+" in mode):
            continue  # only binary read-write/update modes can patch in place
        literal_path = _dbf_artifact_path_argument(node)
        literal_dbf_target = (
            literal_path is not None and DBF_ARTIFACT_RE.search(literal_path) is not None
        )
        if literal_dbf_target or module_has_dbf_context:
            raise BoundaryViolation(
                f"in-place binary patching of a DBF/FPT artifact (mode {mode!r}) — "
                "the historical raw DBF patch path wrote DBF bytes in place; 1.0 "
                "delegates all DBF/FPT parsing/writing to public dbfbridge"
            )


def check_module(label: str, source: str) -> None:
    """Apply all source-level boundary rules to one module's source text."""
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        raise BoundaryViolation(f"{label}: source does not parse: {exc}") from exc
    _check_imports(tree)
    _check_names_and_attributes(tree)
    _check_calls(tree, source)
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


def test_guard_rejects_explicit_dbf_binary_update() -> None:
    _assert_forbidden(
        "def repair_table(path):\n"
        "    with open('table.dbf', 'r+b') as handle:\n"
        "        handle.seek(0)\n"
        "        handle.write(b'x')\n",
        r"in-place binary patching of a DBF/FPT artifact",
    )


def test_guard_rejects_explicit_fpt_binary_update() -> None:
    _assert_forbidden(
        "def repair_memo(path):\n"
        "    with open('memo.fpt', mode='r+b') as handle:\n"
        "        handle.write(b'x')\n",
        r"in-place binary patching of a DBF/FPT artifact",
    )


def test_guard_rejects_binary_update_with_dbf_artifact_module_context() -> None:
    # No literal DBF path, but the module demonstrably targets DBF artifacts.
    _assert_forbidden(
        "TABLE_GLOB = '*.dbf'\n\n"
        "def patch(handle_path):\n"
        "    with open(handle_path, 'r+b') as handle:\n"
        "        handle.write(b'x')\n",
        r"in-place binary patching of a DBF/FPT artifact",
    )


def test_guard_rejects_binary_update_with_dbf_layout_surgery_context() -> None:
    # Header/record-length surgery in the module is DBF/FPT layout context.
    _assert_forbidden(
        "HEADER_LENGTH = 32\n\n"
        "def patch(handle_path):\n"
        "    with open(handle_path, 'r+b') as handle:\n"
        "        handle.seek(HEADER_LENGTH)\n"
        "        handle.write(b'x')\n",
        r"in-place binary patching of a DBF/FPT artifact",
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


def test_guard_allows_unrelated_binary_update_io() -> None:
    # Binary random-access/update I/O on an unrelated artifact is NOT a
    # DBF/FPT boundary violation: the DBF/FPT ownership rule, not generic
    # binary I/O, is what the architecture forbids.
    _assert_allowed(
        "def update_binary_cache(path):\n"
        "    with open(path, 'r+b') as handle:\n"
        "        handle.seek(0)\n"
        "        handle.write(b'x')\n"
    )
    _assert_allowed(
        "def update_binary_cache(path):\n"
        "    with open(path, mode='rb+') as handle:\n"
        "        handle.seek(0)\n"
        "        handle.write(b'x')\n"
    )


def test_guard_allows_generic_struct_use() -> None:
    # struct without DBF artifact references in the same module is allowed.
    _assert_allowed(
        "import struct\n\n"
        "def encode(value):\n"
        "    return struct.pack('<i', value)\n"
    )


def test_guard_allows_text_append_mode() -> None:
    # A text-mode reopen (no 'b') is not the raw-DBF patch path.
    _assert_allowed(
        "def append_log(path, line):\n"
        "    with open(path, 'a') as handle:\n"
        "        handle.write(line)\n"
    )


# ---------------------------------------------------------------------------
# REQ-P1-006 boundary regression: no manual/raw DBF writer anywhere
# ---------------------------------------------------------------------------

#: Every Python source in the active package, the test suite and the tooling.
WRITER_SCAN_ROOTS = (
    Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer",
    Path(__file__).resolve().parents[1] / "tests",
    Path(__file__).resolve().parents[1] / "tools",
)

#: The single, narrowly documented exception: the three pre-existing malformed
#: synthetic-fixture mutations of the approved P0 fixture generator. They are
#: byte-level test tooling (deterministic corrupting mutations of wholly
#: synthetic tables), NOT a DBF writer, and their existence and count are
#: pinned by ``test_raw_writer_exception_is_the_documented_generator_mutations``.
RAW_WRITER_ALLOWLIST: dict[str, str] = {
    "tools/generate_p0_fixtures.py": (
        "the three pre-existing, narrowly documented malformed synthetic "
        "fixture mutations (_corrupt_truncate_records, _corrupt_version_byte, "
        "_corrupt_header_length)"
    ),
}

#: The exact three documented mutation helpers the exception covers.
_GENERATOR_MUTATION_FUNCTIONS = (
    "_corrupt_header_length",
    "_corrupt_truncate_records",
    "_corrupt_version_byte",
)


def _tree_sources() -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for root in WRITER_SCAN_ROOTS:
        for path in sorted(root.rglob("*.py")):
            files.append((path.relative_to(root).as_posix(), path))
    return files


def _manual_dbf_writer_evidence(source: str) -> str | None:
    """Return a violation reason when *source* builds/patches DBF bytes itself.

    AST-based so that string literals (documentation, guard self-test
    snippets) are never mistaken for code. Mirrors the accepted production
    guard rules — direct ``dbf`` engine use, in-place binary DBF update, and
    struct-based DBF/FPT byte surgery — applied to tests and tools as well.
    (The raw-record sentinel rule stays enforced on production code by
    :func:`check_module`; the sentinel constant defined by this guard module
    itself is documentation, not a writer.)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    has_dbf_context = bool(DBF_ARTIFACT_RE.search(source))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            try:
                _check_imports(node)  # type: ignore[arg-type]
            except BoundaryViolation as violation:
                return str(violation)
            continue
        if not isinstance(node, ast.Call):
            continue
        if _is_open_call(node):
            mode = _open_modes(node).replace(" ", "")
            if "b" in mode and "+" in mode and has_dbf_context:
                return f"in-place binary DBF/FPT update (mode {mode!r})"
        if isinstance(node.func, ast.Attribute):
            chain = _base_attribute_chain(node.func)
            if chain is not None:
                base, attrs = chain
                if base.id == "struct" and attrs and attrs[0] in {
                    "pack", "pack_into", "unpack", "unpack_from",
                } and has_dbf_context:
                    return "struct-based DBF/FPT byte surgery"
    return None


def test_no_manual_dbf_writer_in_src_tests_tools() -> None:
    """No raw/manual DBF writer exists in src, tests or tools (REQ-P1-006).

    Synthetic DBF/FPT data is produced exclusively through the public
    ``dbfbridge`` write boundary. The only allowed byte-level DBF handling in
    the repository is the narrowly documented malformed-fixture mutation set
    inside the approved P0 generator (pinned below).
    """
    repo_root = Path(__file__).resolve().parents[1]
    violations: list[str] = []
    for label, path in _tree_sources():
        rel = path.relative_to(repo_root).as_posix()
        evidence = _manual_dbf_writer_evidence(path.read_text(encoding="utf-8"))
        if evidence is None:
            continue
        if rel in RAW_WRITER_ALLOWLIST:
            continue
        violations.append(f"{label}: {evidence}")
    assert not violations, "manual DBF writer logic found: " + "; ".join(violations)


def test_raw_writer_exception_is_the_documented_generator_mutations() -> None:
    # The allowlist is exactly one file, and that file contains exactly the
    # three documented mutation helpers — the exception cannot silently grow.
    assert set(RAW_WRITER_ALLOWLIST) == {"tools/generate_p0_fixtures.py"}
    generator = WRITER_SCAN_ROOTS[2] / "generate_p0_fixtures.py"
    assert generator.exists()
    source = generator.read_text(encoding="utf-8")
    corrupt_functions = sorted(re.findall(r"^def (_corrupt_\w+)\(", source, re.M))
    assert corrupt_functions == sorted(_GENERATOR_MUTATION_FUNCTIONS)
    assert "implements no DBF/FPT/CDX/IDX/DBC parser or writer" in source


def test_writer_scanner_flags_raw_dbf_writer_snippets() -> None:
    # The regression scanner itself detects the removed test-side raw writer
    # pattern (header/field-descriptor/record construction via struct).
    raw_writer_snippet = (
        "import struct\n"
        "from pathlib import Path\n"
        "\n"
        "def _raw_dbf(path, fields, records):\n"
        "    header_length = 32 + 32 * len(fields) + 1\n"
        "    record_length = 1 + sum(length for _n, _t, length, _f in fields)\n"
        "    header = bytearray(32)\n"
        "    struct.pack_into('<H', header, 8, header_length)\n"
        "    struct.pack_into('<H', header, 10, record_length)\n"
        "    path.write_bytes(bytes(header) + b'')\n"
    )
    evidence = _manual_dbf_writer_evidence(raw_writer_snippet)
    assert evidence is not None
    assert "struct-based DBF/FPT byte surgery" in evidence


def test_writer_scanner_allows_public_dbfbridge_writes() -> None:
    # Public dbfbridge writes and unrelated binary I/O stay allowed.
    assert _manual_dbf_writer_evidence(
        "import dbfbridge\n\n"
        "def make_table(path):\n"
        "    dbfbridge.write_table(path / 'table.dbf', schema=schema, records=[])\n"
    ) is None
    assert _manual_dbf_writer_evidence(
        "import struct\n\n"
        "def encode(value):\n"
        "    return struct.pack('<i', value)\n"
    ) is None


# ---------------------------------------------------------------------------
# REQ-P1-007 import/capability path purity (static regressions)
# ---------------------------------------------------------------------------
#: Modules executed by the normal public import/capabilities path
#: (``import dbf_anonymizer`` -> api -> planning/preflight/discovery/
#: _capability/capabilities + models/errors).
IMPORT_PATH_MODULES = (
    "__init__.py",
    "api.py",
    "capabilities.py",
    "_capability.py",
    "models.py",
    "errors.py",
    "preflight.py",
    "planning.py",
    "discovery.py",
)

#: COM/ole-automation and VFP integration modules: importing any of them from
#: the public import/capability path would violate REQ-P1-007/REQ-P6-001.
COM_VFP_IMPORT_ROOTS = frozenset(
    {
        "win32com",
        "win32api",
        "win32gui",
        "win32process",
        "win32ui",
        "win32clipboard",
        "win32file",
        "pythoncom",
        "comtypes",
        "pywintypes",
        "ctypes",
    }
)

#: MCP/server frameworks must stay outside the synchronous, transport-neutral
#: Python API (REQ-P7-001).
MCP_SERVER_IMPORT_ROOTS = frozenset(
    {
        "mcp",
        "fastmcp",
        "mcp_vfp9sp2_toolchain",
        "flask",
        "django",
        "fastapi",
        "starlette",
        "uvicorn",
    }
)

#: Runtime package installation is forbidden (REQ-P0-002/REQ-P7-004).
PACKAGE_INSTALL_IMPORT_ROOTS = frozenset(
    {"pip", "setuptools", "pkg_resources", "ensurepip", "venv"}
)


def _top_level_import_roots(source: str) -> set[str]:
    tree = ast.parse(source)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # intra-package relative import
                continue
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_import_capability_path_imports_no_com_vfp_backend() -> None:
    for module_name in IMPORT_PATH_MODULES:
        path = SRC_ROOT / module_name
        assert path.exists(), module_name
        roots = _top_level_import_roots(path.read_text(encoding="utf-8"))
        offending = sorted(roots & COM_VFP_IMPORT_ROOTS)
        assert not offending, f"{module_name}: COM/VFP/ole import: {offending}"


def test_no_mcp_or_server_framework_imports_in_the_python_api() -> None:
    offending: list[str] = []
    for path in _production_sources():
        roots = _top_level_import_roots(path.read_text(encoding="utf-8"))
        offending_roots = sorted(roots & MCP_SERVER_IMPORT_ROOTS)
        if offending_roots:
            offending.append(
                f"{path.relative_to(SRC_ROOT)}: {offending_roots}"
            )
    assert not offending, "MCP/server framework import: " + "; ".join(offending)


def test_no_runtime_package_installation_imports() -> None:
    offending: list[str] = []
    for path in _production_sources():
        roots = _top_level_import_roots(path.read_text(encoding="utf-8"))
        offending_roots = sorted(roots & PACKAGE_INSTALL_IMPORT_ROOTS)
        if offending_roots:
            offending.append(
                f"{path.relative_to(SRC_ROOT)}: {offending_roots}"
            )
    assert not offending, "runtime package installation: " + "; ".join(offending)


# ---------------------------------------------------------------------------
# REQ-P2-001/002/003 vault-layer boundaries (static regressions)
# ---------------------------------------------------------------------------
VAULT_MODULES = (
    "vault/__init__.py",
    "vault/schema.py",
    "vault/store.py",
    "vault/mappings.py",
    "vault/transactions.py",
)

#: The source-read-only public operations must never reach the vault layer:
#: vault creation belongs to the future execution engine (REQ-P1-005/006).
SOURCE_READ_ONLY_MODULES = ("api.py", "planning.py", "preflight.py")


def test_vault_modules_exist_and_own_the_vault_layer() -> None:
    for module_name in VAULT_MODULES:
        assert (SRC_ROOT / module_name).is_file(), module_name


def test_vault_layer_imports_no_dbfbridge_namespace() -> None:
    # The vault MUST NOT parse DBF/FPT and has no reason to import the
    # dbfbridge namespace at all — public or private.
    for module_name in VAULT_MODULES:
        source = (SRC_ROOT / module_name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] != "dbfbridge", module_name
            elif isinstance(node, ast.ImportFrom):
                full = _import_full_name(node)
                assert not full.startswith("dbfbridge"), module_name


def test_vault_layer_imports_no_com_vfp_backend() -> None:
    for module_name in VAULT_MODULES:
        source = (SRC_ROOT / module_name).read_text(encoding="utf-8")
        roots = _top_level_import_roots(source)
        offending = sorted(roots & COM_VFP_IMPORT_ROOTS)
        assert not offending, f"{module_name}: COM/VFP/ole import: {offending}"


def test_vault_layer_avoids_weak_random_generators() -> None:
    # Pseudonym ALLOCATION is REQ-P2-004; the storage foundation must not
    # even accidentally wire a weak deterministic generator into the vault.
    for module_name in VAULT_MODULES:
        source = (SRC_ROOT / module_name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] != "random", module_name
            elif isinstance(node, ast.ImportFrom):
                full = _import_full_name(node)
                assert not full.startswith("random"), module_name


def test_source_read_only_operations_never_instantiate_the_vault() -> None:
    for module_name in SOURCE_READ_ONLY_MODULES:
        source = (SRC_ROOT / module_name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                full = _import_full_name(node)
                dotted = full.lstrip(".")
                assert not dotted.startswith("vault"), module_name
                assert dotted != "vault", module_name
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "vault", module_name
                    assert not alias.name.startswith("dbf_anonymizer.vault"), module_name


def test_no_sqlite_database_files_in_package_or_fixtures() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scanned = [repo_root / "src" / "dbf_anonymizer", repo_root / "tests" / "fixtures"]
    offending: list[str] = []
    for root in scanned:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.name
            if (
                path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}
                or name.endswith(("-wal", "-shm", ".journal"))
            ):
                offending.append(str(path.relative_to(repo_root)))
    assert not offending, f"committed SQLite vault artifacts: {offending}"
