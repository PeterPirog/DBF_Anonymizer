import os
from pathlib import Path

import pytest

from dbf_anonymizer import self_test
from dbf_anonymizer.vfp import (
    VfpError,
    VfpVerification,
    companion_cdx,
    dbf_has_structural_index,
    rebuild_companion_cdx,
    validate_vfp_executable,
)


def test_companion_cdx_is_case_insensitive(tmp_path: Path):
    dbf = tmp_path / "INDEXY_4.DBF"
    dbf.write_bytes(b"dbf")
    cdx = tmp_path / "indexy_4.cDx"
    cdx.write_bytes(b"definitions")

    assert companion_cdx(dbf) == cdx


def test_rebuild_copies_definitions_before_reindex(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    source_dbf = source / "table.dbf"
    source_dbf.write_bytes(b"source")
    (source / "table.cdx").write_bytes(b"definitions")
    target_dbf = target / "table.dbf"
    target_dbf.write_bytes(b"target")

    def fake_run(dbf, *, progid, reindex, timeout):
        assert Path(dbf).with_suffix(".cdx").read_bytes() == b"definitions"
        assert reindex is True
        return VfpVerification(str(dbf), 3, 2, ("ID", "NAME"), True)

    monkeypatch.setattr("dbf_anonymizer.vfp._run_vfp", fake_run)

    result = rebuild_companion_cdx(source_dbf, target_dbf)

    assert result is not None
    assert result.tag_count == 2
    assert (target / "table.cdx").read_bytes() == b"definitions"


def test_structural_index_flag_is_read_from_dbf_header(tmp_path: Path):
    dbf = tmp_path / "table.dbf"
    header = bytearray(29)
    dbf.write_bytes(header)
    assert not dbf_has_structural_index(dbf)

    header[28] = 1
    dbf.write_bytes(header)
    assert dbf_has_structural_index(dbf)


def test_vfp_executable_path_is_validated(tmp_path: Path):
    executable = tmp_path / "vfp9.exe"
    executable.write_bytes(b"fixture")

    assert validate_vfp_executable(executable) == executable.resolve()
    with pytest.raises(VfpError, match="VFP_EXECUTABLE_MISSING"):
        validate_vfp_executable(tmp_path / "missing.exe")


@pytest.mark.vfp
def test_real_vfp_fixture_roundtrip():
    fixture = os.environ.get("DBF_ANONYMIZER_VFP_FIXTURE")
    if not fixture:
        pytest.skip("Ustaw DBF_ANONYMIZER_VFP_FIXTURE na katalog DBF/CDX")

    report = self_test(Path(fixture), workers=2, batch_size=1000)

    assert report.successful, [table.errors for table in report.tables if table.errors]
