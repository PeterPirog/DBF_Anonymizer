"""P0 architecture-boundary regression evidence for REQ-P0-001/REQ-P0-002.

Static checks that fail if the active ``src/dbf_anonymizer`` production code
reintroduces the superseded 0.3 DBF/FPT paths:

- the historical ``dbf_bridge`` import namespace or dbfbridge private
  internals (anything below the public ``dbfbridge`` top-level namespace);
- direct use of the ``dbf`` library as DBF/FPT engine;
- production use of ``export_dbf`` / ``reconstruct_dbf`` (the JSONL
  pipeline) or the historical raw DBF patch path;
- legacy 0.3 module-layout names tied to the raw patch / JSONL pipeline.

The checks enforce the DBF/FPT ownership boundary only; they deliberately do
not ban generic implementation style (for example Python's ``struct`` module)
for unrelated future uses.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"

#: Superseded 0.3 module-layout names tied to the raw patch / JSONL pipeline.
FORBIDDEN_MODULE_NAMES = (
    "rawpatch.py",
    "layout.py",
    "tableio.py",
    "jsonstream.py",
    "dictionary.py",
    "global_store.py",
)

#: The raw-record restoration sentinel of the 0.3 raw-patch path.
RAW_RECORD_SENTINEL = "__dbfbridge_raw_record__"

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "import from the historical dbf_bridge namespace",
        re.compile(r"^\s*(?:from\s+dbf_bridge\b|import\s+dbf_bridge\b)", re.MULTILINE),
    ),
    (
        "import of a dbfbridge private internal (only the public dbfbridge "
        "top-level namespace is allowed)",
        re.compile(r"^\s*(?:from\s+dbfbridge\.\S+|import\s+dbfbridge\.)", re.MULTILINE),
    ),
    (
        "direct use of the dbf library as DBF/FPT engine",
        re.compile(r"^\s*(?:from\s+dbf\s+import\s|import\s+dbf\s*(?:as\s+\w+)?\s*$)", re.MULTILINE),
    ),
    (
        "production use of export_dbf",
        re.compile(r"\bexport_dbf\b"),
    ),
    (
        "production use of reconstruct_dbf",
        re.compile(r"\breconstruct_dbf\b"),
    ),
    (
        "historical raw DBF patch path (raw field bytes written back with "
        "r+b; struct-based DBF byte surgery is delegated to dbfbridge)",
        re.compile(r"[\"']r\+b[\"']"),
    ),
)


def _production_sources() -> list[Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def test_production_sources_exist() -> None:
    assert _production_sources(), "the active package tree is missing"


def test_no_superseded_pipeline_modules() -> None:
    present = {path.name for path in _production_sources()}
    assert not present & set(FORBIDDEN_MODULE_NAMES), sorted(present & set(FORBIDDEN_MODULE_NAMES))


def test_no_legacy_raw_record_sentinel() -> None:
    for path in _production_sources():
        assert RAW_RECORD_SENTINEL not in path.read_text(encoding="utf-8"), path


def test_no_forbidden_dbf_boundary_imports_or_operations() -> None:
    for path in _production_sources():
        source = path.read_text(encoding="utf-8")
        for description, pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(source)
            assert match is None, f"{path}: {description} (matched {match!r})"


def test_struct_is_not_used_for_dbf_byte_surgery() -> None:
    """struct-based DBF/FPT byte surgery stays behind the dbfbridge boundary.

    Scoped to the DBF/FPT ownership boundary (header/record byte handling for
    DBF/FPT artifacts), not a blanket ban on the ``struct`` module.
    """
    dbf_byte_surgery = re.compile(
        r"struct\.(?:un)?pack", re.MULTILINE
    )
    dbf_artifact = re.compile(r"\.dbf\b|\.fpt\b|\.cdx\b|header_length|record_length", re.IGNORECASE)
    for path in _production_sources():
        source = path.read_text(encoding="utf-8")
        if dbf_byte_surgery.search(source):
            assert not dbf_artifact.search(source), (
                f"{path}: struct-based DBF/FPT byte surgery outside the dbfbridge boundary"
            )


def test_dbfbridge_usage_is_public_namespace_only() -> None:
    """When production code touches DBF/FPT at all, only ``import dbfbridge``
    or ``from dbfbridge import <public top-level symbols>`` is allowed; both
    forbidden forms are already rejected above, so assert the allowed forms
    compile to references of the public namespace."""
    for path in _production_sources():
        source = path.read_text(encoding="utf-8")
        assert "dbf_bridge" not in source, path
        assert not re.search(r"dbfbridge\.\w", source), path