"""Fresh typed DBF/FPT reconstruction evidence for REQ-P4-003.

All fixtures are synthetic and created under ``tmp_path``. Physical-byte
inspection and source-only sentinel injection occur only in this test module;
production sees the fixtures exclusively through public dbfbridge Direct Read.
"""

from __future__ import annotations

import ast
from pathlib import Path

import dbfbridge
import pytest

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import direct_io, run_two_pass
from support.memo_tables import field, read_memo_records, write_memo_table
from support.numeric_tables import numeric_field, write_numeric_table_with_deleted


_LOGICAL_SENTINEL = "P4003-ORIGINAL-LOGICAL-SENTINEL-9F2C7A1D"
_PADDING_SENTINEL = b"P4003-PADDING-ONLY-7B1E4C9A"
_HEADER_SENTINEL = b"HDR-P4003-X7"
_FPT_SENTINEL = b"P4003-UNREACHABLE-FPT-BLOCK-5D8A2C7E"
_ENGINE_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer" / "engine"
_RECONSTRUCTION_MODULES = ("direct_io.py", "pass2.py", "run.py")


def _run(source_root: Path, tmp_path: Path):
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)
    result = run_two_pass(plan)
    return result, output_root


def test_logical_sentinel_is_transformed_for_active_and_deleted_records(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source = write_numeric_table_with_deleted(
        source_root,
        "logical.dbf",
        (numeric_field("SECRET", "C", 48),),
        [
            ({"SECRET": _LOGICAL_SENTINEL}, False),
            ({"SECRET": _LOGICAL_SENTINEL}, True),
        ],
    )
    sentinel = _LOGICAL_SENTINEL.encode("ascii")
    assert sentinel in source.read_bytes()

    result, output_root = _run(source_root, tmp_path)
    output_path = output_root / "logical.dbf"
    output = tuple(dbfbridge.iter_records(output_path, include_deleted=True))

    assert result.pass2_records_written == 2
    assert [record.deleted for record in output] == [False, True]
    assert output[0].values["SECRET"] == output[1].values["SECRET"]
    assert output[0].values["SECRET"] != _LOGICAL_SENTINEL
    assert sentinel not in output_path.read_bytes()


def test_source_record_padding_sentinel_is_not_reconstructed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = write_numeric_table_with_deleted(
        source_root,
        "padding.dbf",
        (numeric_field("PUBLIC", "C", 12),),
        [({"PUBLIC": "VISIBLE"}, False), ({"PUBLIC": "SECOND"}, False)],
    )
    public_schema = dbfbridge.read_schema(source)
    eof_offset = int(public_schema.header_length) + int(
        public_schema.record_count
    ) * int(public_schema.record_length)
    raw = source.read_bytes()
    # TEST-ONLY: the sentinel is placed in unreferenced physical slack beyond
    # the last record (before the EOF marker when one is present, appended
    # after the record area otherwise).  The public logical records are
    # untouched; production never parses this region.
    assert eof_offset <= len(raw)
    if raw[eof_offset : eof_offset + 1] == b"\x1a":
        source.write_bytes(raw[:eof_offset] + _PADDING_SENTINEL + raw[eof_offset:])
    else:
        source.write_bytes(raw + _PADDING_SENTINEL)

    source_records = tuple(dbfbridge.iter_records(source, include_deleted=True))
    assert [record.values["PUBLIC"] for record in source_records] == [
        "VISIBLE",
        "SECOND",
    ]
    assert _PADDING_SENTINEL in source.read_bytes()

    _result, output_root = _run(source_root, tmp_path)
    output = output_root / "padding.dbf"
    output_records = tuple(dbfbridge.iter_records(output, include_deleted=True))
    assert len(output_records) == 2
    assert [record.values["PUBLIC"] for record in output_records] != [
        "VISIBLE",
        "SECOND",
    ]
    assert _PADDING_SENTINEL not in output.read_bytes()


def test_unused_header_sentinel_is_not_reconstructed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = write_numeric_table_with_deleted(
        source_root,
        "header.dbf",
        (numeric_field("PUBLIC", "C", 12),),
        [({"PUBLIC": "VISIBLE"}, False)],
    )
    # VFP header bytes 16..27 are reserved. This test-only mutation leaves
    # the public schema and logical record stream valid.
    assert len(_HEADER_SENTINEL) == 12
    with source.open("r+b") as stream:
        stream.seek(16)
        stream.write(_HEADER_SENTINEL)
    assert _HEADER_SENTINEL in source.read_bytes()
    assert [
        record.values["PUBLIC"]
        for record in dbfbridge.iter_records(source, include_deleted=True)
    ] == ["VISIBLE"]

    _result, output_root = _run(source_root, tmp_path)
    output = output_root / "header.dbf"
    assert tuple(dbfbridge.iter_records(output, include_deleted=True))
    assert _HEADER_SENTINEL not in output.read_bytes()


def test_unreachable_fpt_sentinel_is_not_reconstructed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    legitimate = "PUBLIC LOGICAL MEMO VALUE"
    source = write_memo_table(
        source_root,
        "memo.dbf",
        (field("NOTE", "M", 4),),
        ({"NOTE": legitimate},),
    )
    source_fpt = source.with_suffix(".fpt")
    with source_fpt.open("ab") as stream:
        stream.write(b"\x00" * 64)
        stream.write(_FPT_SENTINEL)

    source_records = read_memo_records(source)
    assert [record.values["NOTE"] for record in source_records] == [legitimate]
    assert all(
        _FPT_SENTINEL not in str(record.values).encode("utf-8")
        for record in source_records
    )
    assert _FPT_SENTINEL in source_fpt.read_bytes()

    _result, output_root = _run(source_root, tmp_path)
    output = output_root / "memo.dbf"
    output_fpt = output.with_suffix(".fpt")
    assert read_memo_records(output)
    assert output_fpt.is_file()
    assert _FPT_SENTINEL not in output_fpt.read_bytes()


def test_each_table_uses_public_writer_once_with_fresh_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    for name, deleted in (("first.dbf", False), ("second.dbf", True)):
        write_numeric_table_with_deleted(
            source_root,
            name,
            (numeric_field("TEXT", "C", 16),),
            [({"TEXT": "PRIVATE-" + name[:5]}, deleted)],
        )

    public_write = direct_io.dbfbridge.write_table
    calls: list[str] = []
    supplied = 0

    def inspect_write(destination: object, **kwargs: object):
        nonlocal supplied
        calls.append(Path(destination).name)  # type: ignore[arg-type]
        records = kwargs["records"]

        def fresh_records():
            nonlocal supplied
            for record in records:  # type: ignore[union-attr]
                supplied += 1
                assert record.raw_record is None
                assert all(str(name).upper() != "_NULLFLAGS" for name in record.values)
                yield record

        kwargs["records"] = fresh_records()
        return public_write(destination, **kwargs)

    monkeypatch.setattr(direct_io.dbfbridge, "write_table", inspect_write)
    result, _output_root = _run(source_root, tmp_path)

    assert calls == ["first.dbf", "second.dbf"]
    assert supplied == result.pass2_records_written == 2


def test_reconstruction_modules_forbid_source_copy_raw_and_private_io() -> None:
    """A narrow AST guard over only the production reconstruction boundary."""
    forbidden_import_roots = {"dbf", "dbfread", "shutil"}
    forbidden_path_io = {"read_bytes", "write_bytes", "read_text", "write_text"}
    forbidden_copy_calls = {"copy", "copy2", "copyfile", "copyfileobj"}
    # VaultDatabase.open is the typed vault handle (no DBF/FPT file IO); every
    # other attribute ``.open(...)`` in the boundary would be a path open.
    allowed_open_receivers = {"VaultDatabase"}

    for filename in _RECONSTRUCTION_MODULES:
        path = _ENGINE_ROOT / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=filename)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".")[0] not in forbidden_import_roots
                    for alias in node.names
                )
                assert all(not alias.name.startswith("dbfbridge.") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert module.split(".")[0] not in forbidden_import_roots
                assert not module.startswith("dbfbridge.")
            elif isinstance(node, ast.Attribute):
                assert node.attr != "raw_record"
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_copy_calls | {"open"}
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in forbidden_copy_calls | forbidden_path_io
                    if node.func.attr == "open":
                        receiver = node.func.value
                        assert (
                            isinstance(receiver, ast.Name)
                            and receiver.id in allowed_open_receivers
                        )
                direct_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if direct_name == "DirectRecord":
                    assert not node.args
                    assert {keyword.arg for keyword in node.keywords} == {
                        "physical_index",
                        "deleted",
                        "values",
                    }
