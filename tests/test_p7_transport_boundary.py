"""REQ-P7-001 synchronous, transport-neutral public API evidence."""

from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import sys
from pathlib import Path
from types import ModuleType

import dbf_anonymizer as public
from dbfbridge import DirectRecord, write_table

from tests.support.memo_tables import field, schema
from tests.test_p1_capability_purity import _assert_clean, _run_isolated_purity_child

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = REPO_ROOT / "examples" / "consumer_adapter.py"
SRC_ROOT = REPO_ROOT / "src" / "dbf_anonymizer"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

PUBLIC_OPERATIONS = (
    "capabilities",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
)

FORBIDDEN_TRANSPORT_ROOTS = frozenset(
    {
        "mcp",
        "fastmcp",
        "mcp_vfp9sp2_toolchain",
        "vfp_toolchain",
        "fastapi",
        "flask",
        "django",
        "starlette",
        "aiohttp",
        "sanic",
        "quart",
        "litestar",
        "tornado",
        "bottle",
        "cherrypy",
        "hypercorn",
        "gunicorn",
        "uvicorn",
        "websockets",
    }
)


def _import_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            roots.add(node.module.split(".")[0])
    return roots


def _load_consumer_adapter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("p7_consumer_adapter", EXAMPLE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_public_operations_are_plain_synchronous_functions() -> None:
    for name in PUBLIC_OPERATIONS:
        operation = getattr(public, name)
        assert inspect.isfunction(operation), name
        assert not inspect.iscoroutinefunction(operation), name
        assert not inspect.isasyncgenfunction(operation), name


def test_production_package_has_no_transport_framework_import() -> None:
    offending: dict[str, list[str]] = {}
    for path in sorted(SRC_ROOT.rglob("*.py")):
        roots = _import_roots(path.read_text(encoding="utf-8"))
        forbidden = sorted(roots & FORBIDDEN_TRANSPORT_ROOTS)
        if forbidden:
            offending[path.relative_to(SRC_ROOT).as_posix()] = forbidden
    assert offending == {}


def test_runtime_dependencies_exclude_transport_frameworks() -> None:
    """Parse the RUNTIME dependency metadata (never dev/test tooling): the
    ``[project]`` dependencies table must introduce no MCP/server/transport
    framework and must keep the exact dbfbridge boundary."""
    import tomllib

    with PYPROJECT_PATH.open("rb") as handle:
        metadata = tomllib.load(handle)
    runtime_dependencies = metadata["project"]["dependencies"]
    assert isinstance(runtime_dependencies, list)
    runtime_roots = set()
    for requirement in runtime_dependencies:
        assert isinstance(requirement, str)
        # Requirement-name root: strip extras/markers/operators conservatively.
        root = re.split(r"[<>=!~\[;\s]", requirement, maxsplit=1)[0]
        runtime_roots.add(root.split(".")[0])
    assert not (runtime_roots & FORBIDDEN_TRANSPORT_ROOTS), sorted(
        runtime_roots & FORBIDDEN_TRANSPORT_ROOTS
    )
    assert "dbfbridge[write]>=1.1.0,<2" in runtime_dependencies


def test_public_annotations_never_reference_transport_frameworks() -> None:
    """REQ-P7-001 (D): no public callable annotation/signature may reference a
    type from a forbidden MCP/server-framework module (AST-based, whole
    production tree)."""
    offending: list[tuple[str, int, str]] = []

    def _annotation_roots(node: ast.expr | None) -> None:
        if node is None:
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                root = child.id.split(".")[0]
                if root in FORBIDDEN_TRANSPORT_ROOTS:
                    offending.append(("<annotation>", 0, root))

    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for argument in (*node.args.args, *node.args.kwonlyargs, *node.args.posonlyargs):
                    _annotation_roots(argument.annotation)
                if node.args.vararg is not None:
                    _annotation_roots(node.args.vararg.annotation)
                if node.args.kwarg is not None:
                    _annotation_roots(node.args.kwarg.annotation)
                _annotation_roots(node.returns)
            elif isinstance(node, ast.AnnAssign):
                _annotation_roots(node.annotation)
            elif isinstance(node, ast.arg):
                _annotation_roots(node.annotation)
    assert offending == [], sorted({item[2] for item in offending})


def test_root_import_starts_no_network_server_or_vfp_runtime(tmp_path: Path) -> None:
    verdict, completed = _run_isolated_purity_child(tmp_path, "import")
    _assert_clean(verdict, completed)


def test_consumer_adapter_uses_only_the_public_package_root() -> None:
    source = EXAMPLE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    dbf_imports: list[str] = []
    public_attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("dbf_anonymizer"):
                    dbf_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").startswith("dbf_anonymizer"):
                dbf_imports.append(node.module or "")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "public"
        ):
            public_attributes.add(node.attr)

    assert dbf_imports == ["dbf_anonymizer"]
    assert public_attributes <= set(public.__all__)
    assert not (_import_roots(source) & FORBIDDEN_TRANSPORT_ROOTS)
    assert not any(isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree))


def test_consumer_adapter_runs_the_public_workflow_on_synthetic_data(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_table(
        source / "people.dbf",
        schema=schema((field("NAME", "C", 16),)),
        records=[
            DirectRecord(
                physical_index=0,
                deleted=False,
                values={"NAME": "SYNTHETIC"},
            )
        ],
    )

    adapter = _load_consumer_adapter()
    result = adapter.run_consumer_workflow(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
    )

    assert isinstance(result.plan, public.Plan)
    assert isinstance(result.preflight, public.PreflightResult)
    assert result.preflight.ready is True
    assert isinstance(result.pseudonymization, public.PseudonymizationResult)
    assert isinstance(result.verification, public.VerificationResult)
    assert result.verification.status is public.VerificationStatus.PASS


# ---------------------------------------------------------------------------
# Installed-wheel consumer proof (REQ-P7-001 external boundary)
# ---------------------------------------------------------------------------


def test_consumer_adapter_works_from_the_installed_wheel(
    tmp_path: Path,
) -> None:
    """The consumer adapter is exercised against the INSTALLED wheel from a
    directory outside the repository: a genuinely isolated child venv
    (``system_site_packages=False``) with only the public pinned dbfbridge
    acceptance artifact and the built wheel; no repository source shadowing
    and no MCP/server framework may be required."""
    import os
    import subprocess
    import venv

    wheelhouse = tmp_path / "build-dist"
    wheelhouse.mkdir()
    built = subprocess.run(  # noqa: S603 - task-owned build of the public wheel
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(wheelhouse)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    wheels = sorted(wheelhouse.glob("dbf_anonymizer-*.whl"))
    assert len(wheels) == 1
    acceptance_pin = (
        (REPO_ROOT / "requirements" / "p0-dbfbridge-tested.txt")
        .read_text(encoding="utf-8")
        .strip()
        .splitlines()[-1]
        .strip()
    )
    assert acceptance_pin.startswith("dbfbridge[write]==")
    environment = tmp_path / "consumer-venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
    interpreter = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    child_pip = [str(interpreter), "-m", "pip", "install", "--no-cache-dir"]
    for command in (
        [*child_pip, acceptance_pin],
        [*child_pip, "--no-deps", str(wheels[0])],
    ):
        installed = subprocess.run(  # noqa: S603 - task-owned isolated environment
            command,
            cwd=tmp_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert installed.returncode == 0, installed.stderr.decode("utf-8", errors="replace")
    # The adapter itself is copied OUT of the repository: the child process
    # must not be able to import repository modules at all.
    adapter_copy = tmp_path / "consumer_adapter.py"
    adapter_copy.write_text(EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    probe = tmp_path / "consumer_probe.py"
    probe.write_text(
        """
import importlib.util
import json
import sys
from pathlib import Path

import dbf_anonymizer as public
from dbfbridge import DirectRecord, write_table

root, adapter_path = map(Path, sys.argv[1:])

# Import-origin proof: BOTH packages come from the child venv site-packages.
for module in (public, __import__("dbfbridge")):
    origin = Path(module.__file__).resolve()
    lowered = {part.lower() for part in origin.parts}
    assert lowered & {"site-packages", "dist-packages"}, origin
    assert root.resolve() in origin.parents, origin
# No repository source shadowing on sys.path.
assert not any(
    entry and "DBF_Anonymizer" in str(Path(entry).resolve())
    for entry in sys.path
    if entry
), sys.path

# Load the copied consumer adapter from OUTSIDE the repository.
spec = importlib.util.spec_from_file_location("consumer_adapter", adapter_path)
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)

# No MCP/server/transport framework may be required by any of the imports.
forbidden = {"mcp", "fastmcp", "fastapi", "flask", "django", "starlette",
             "aiohttp", "sanic", "quart", "litestar", "tornado", "bottle",
             "cherrypy", "hypercorn", "gunicorn", "uvicorn", "websockets"}
imported = {name.split(".")[0] for name in sys.modules}
assert not (imported & forbidden), sorted(imported & forbidden)

# Exercise the thin synchronous consumer boundary end to end.
from pathlib import PurePath

from dbfbridge import FieldInfo, TableSchema

source = adapter_path.parent / "source"
source.mkdir()
name_field = FieldInfo(
    ordinal=0,
    name="NAME",
    dbf_type="C",
    length=16,
    decimal_count=0,
    address=0,
    flags=0,
    index_field_flag=0,
    autoincrement_next_value=0,
    autoincrement_step=1,
    is_memo=False,
    is_binary=False,
    supported=True,
)
table_schema = TableSchema(
    path=PurePath("memory:synthetic-consumer"),
    record_count=0,
    header_length=32 + 32 * 1 + 1,
    record_length=16 + 1,
    language_driver=0xC8,
    encoding="cp1250",
    has_memo=False,
    has_memo_flag=False,
    has_structural_cdx=False,
    is_database_container=False,
    dbc_bound=False,
    dbc_backlink_path=None,
    table_flags=0,
    fields=[name_field],
    warnings=(),
    dbversion_byte=0x30,
    dbversion_name="Visual FoxPro",
    last_update="2026-01-01",
    incomplete_transaction=False,
    encryption_flag=False,
    memo_companion_format=None,
    memo_companion_present=False,
    memo_companion_path=None,
    memo_companion_size_bytes=None,
    memo_block_size=64,
    memo_next_free_block=None,
    companion_cdx_present=False,
    companion_cdx_path=None,
)
write_table(
    source / "people.dbf",
    schema=table_schema,
    records=[DirectRecord(physical_index=0, deleted=False, values={"NAME": "SYNTHETIC"})],
)
result = adapter_module.run_consumer_workflow(
    source,
    adapter_path.parent / "output",
    adapter_path.parent / "vault" / "dictionary.sqlite3",
)
assert isinstance(result.plan, public.Plan)
assert result.preflight.ready is True
assert isinstance(result.pseudonymization, public.PseudonymizationResult)
assert isinstance(result.verification, public.VerificationResult)
assert result.verification.status is public.VerificationStatus.PASS
# Public JSON-safe representations travel the boundary without private types.
payload = json.dumps(result.plan.to_dict())
assert payload and "SYNTHETIC" not in payload
capabilities = public.capabilities()
assert json.dumps(capabilities.to_dict())
""".strip()
        + "\n",
        encoding="utf-8",
    )
    child_env = os.environ.copy()
    child_env.pop("PYTHONPATH", None)
    checked = subprocess.run(  # noqa: S603 - task-owned installed-wheel probe
        [str(interpreter), str(probe), str(environment), str(adapter_copy)],
        cwd=tmp_path,
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr.decode("utf-8", errors="replace")
