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
        "starlette",
        "aiohttp",
        "uvicorn",
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
    pyproject = PYPROJECT_PATH.read_text(encoding="utf-8")
    for root in FORBIDDEN_TRANSPORT_ROOTS:
        assert re.search(rf'["\']{re.escape(root)}(?:[<>=!~\[]|["\'])', pyproject) is None
    assert '"dbfbridge[write]>=1.1.0,<2"' in pyproject


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
