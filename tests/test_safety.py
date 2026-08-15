import json
from pathlib import Path

import pytest

from dbf_anonymizer.manifest import write_manifest
from dbf_anonymizer.pipeline import _validate_disjoint_paths


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("source", "source"),
        ("source", "source/output"),
        ("source/output", "source"),
    ],
)
def test_overlapping_operation_paths_are_rejected(
    tmp_path: Path,
    first: str,
    second: str,
):
    with pytest.raises(ValueError, match="PATH_OVERLAP"):
        _validate_disjoint_paths(
            ("first", tmp_path / first),
            ("second", tmp_path / second),
        )


def test_manifest_does_not_expose_absolute_source_path(tmp_path: Path):
    source = tmp_path / "private" / "LegacyDB"
    output = tmp_path / "published"
    source.mkdir(parents=True)
    output.mkdir()
    (output / "table.dbf").write_bytes(b"dbf")

    manifest_path = write_manifest(
        output,
        operation="anonymize",
        source=source,
        tables=[],
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert payload["format"] == 2
    assert payload["source"] == "LegacyDB"
    assert payload["source_path_kind"] == "basename"
    assert str(tmp_path) not in manifest_path.read_text(encoding="utf-8")
