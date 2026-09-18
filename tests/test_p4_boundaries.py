"""Phase 4 architecture-boundary guards and privacy canaries (REQ-P4-001).

Static production-source guards (the actual src/dbf_anonymizer engine
modules, not just tests) plus canary leakage tests over the engine's public
boundaries: progress events, typed errors, the run result and filenames.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from dbf_anonymizer.engine import direct_io
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
)

ENGINE_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer" / "engine"

_FORBIDDEN_ENGINE_IMPORTS = (
    "dbfread",
    "import dbf\n",
    "from dbf ",
    "import dbf ",
    "socket",
    "urllib",
    "requests",
    "http.client",
    "subprocess",
    "ctypes",
    "win32com",
    "win32pipe",
    "pywintypes",
    "jsonl",
    "reconstruct_dbf",
    "export_dbf",
)


def _engine_sources() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in sorted(ENGINE_ROOT.rglob("*.py"))
    }


def test_engine_sources_never_import_forbidden_modules() -> None:
    """The production Phase 4 modules perform no IO outside the boundary.

    AST-based guard over the ACTUAL production sources: no direct
    ``dbfread``/``dbf`` import, no network module, no COM/VFP automation,
    no ``ctypes``/``subprocess`` and no JSONL bridge module.
    """
    import ast

    forbidden_roots = {
        "dbfread",
        "dbf",
        "socket",
        "urllib",
        "urllib.request",
        "requests",
        "http",
        "http.client",
        "subprocess",
        "ctypes",
        "win32com",
        "win32pipe",
        "pywintypes",
    }
    for path, source in _engine_sources().items():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in forbidden_roots, (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in forbidden_roots, (
                    f"{path.name} imports from {node.module}"
                )
            elif isinstance(node, ast.Name):
                assert node.id not in {"export_dbf", "reconstruct_dbf"}, (
                    f"{path.name} references a superseded pipeline operation"
                )


def test_engine_sources_have_no_jsonl_record_transport() -> None:
    """No *.jsonl artifact is ever created or referenced by the engine."""
    for path, source in _engine_sources().items():
        assert ".jsonl" not in source, f"{path.name} references .jsonl"
        assert not re.search(r"\.csv\b", source), f"{path.name} creates CSV"


def test_engine_never_touches_private_dbfbridge_namespaces() -> None:
    """Only the plain public dbfbridge namespace is referenced.

    The public dunder ``__version__`` access is allowed (the P0 guard
    allows it too); underscore-private symbols and submodules are not.
    """
    for path, source in _engine_sources().items():
        for match in re.finditer(r"dbfbridge\.(\w+)", source):
            attribute = match.group(1)
            if attribute.startswith("__") and attribute.endswith("__"):
                continue  # public dunder version access
            assert not attribute.startswith("_"), (
                f"{path.name} references the private dbfbridge symbol "
                f"dbfbridge.{attribute}"
            )


def test_engine_public_boundaries_never_leak_canaries(tmp_path: Path) -> None:
    """Canaries: originals/pseudonyms/paths never reach the run boundaries."""
    from dbf_anonymizer import build_plan
    from dbf_anonymizer.engine import run_two_pass
    from tests.support.numeric_tables import numeric_field, write_numeric_table

    canary_text = "CNDY-9X"
    document = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "data.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "ref.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "data.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("AMT", "N", 8)),
        [{"CUST_ID": canary_text, "AMT": 1}, {"CUST_ID": "OTHER", "AMT": 2}],
    )
    write_numeric_table(
        source_root,
        "ref.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": canary_text}, {"CUST_ID": "OTHER"}],
    )
    plan = build_plan(
        str(source_root),
        str(tmp_path / "out"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
        relationship_document=document,
    )
    events: list[object] = []

    def progress(event: object) -> None:
        events.append(event)

    result = run_two_pass(plan, progress=progress)
    boundary = str(result)
    for event in events:
        boundary += "|" + repr(event)
        if hasattr(event, "to_dict"):
            boundary += "|" + json.dumps(event.to_dict(), sort_keys=True)
    assert canary_text not in boundary
    assert "OTHER" not in boundary
    assert "C:\\" not in boundary
    assert "vault" not in boundary.lower()
    assert "dictionary.sqlite3" not in boundary


def test_engine_errors_never_leak_canaries(tmp_path: Path) -> None:
    """Typed engine refusals stay value-free (the nullable-text refusal)."""
    from dbf_anonymizer import PathError, build_plan
    from dbf_anonymizer.engine import run_two_pass

    canary_text = "CNDY-NUL"
    document = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "data.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "ref.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    write_numeric_table(
        tmp_path,
        "data.dbf",
        (
            numeric_field("CUST_ID", "C", 8),
            numeric_field("NOTE", "C", 4, flags=NULLABLE_FLAG),
        ),
        [{"CUST_ID": canary_text, "NOTE": "x"}],
    )
    write_numeric_table(
        tmp_path,
        "ref.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": canary_text}],
    )
    plan = build_plan(
        str(tmp_path),
        str(tmp_path / "out"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
        relationship_document=document,
    )
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)
    boundary = (
        str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
    )
    assert canary_text not in boundary
    assert "C:\\" not in boundary
    _ = PathError
