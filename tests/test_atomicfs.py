from pathlib import Path

import pytest

from dbf_anonymizer.atomicfs import DirectoryTransaction


def test_directory_transaction_publishes_all_targets(tmp_path: Path):
    first = tmp_path / "output"
    second = tmp_path / "dictionary"
    transaction = DirectoryTransaction(first, second)
    transaction.prepare()
    (transaction.stage_for(first) / "data.dbf").write_bytes(b"new-data")
    (transaction.stage_for(second) / "dictionary.sqlite3").write_bytes(b"new-map")

    transaction.commit(overwrite=True)

    assert (first / "data.dbf").read_bytes() == b"new-data"
    assert (second / "dictionary.sqlite3").read_bytes() == b"new-map"


def test_directory_transaction_abort_preserves_previous(tmp_path: Path):
    final = tmp_path / "output"
    final.mkdir()
    (final / "old.txt").write_text("old", encoding="utf-8")
    transaction = DirectoryTransaction(final)
    transaction.prepare()
    (transaction.stage_for(final) / "new.txt").write_text("new", encoding="utf-8")

    transaction.abort()

    assert (final / "old.txt").read_text(encoding="utf-8") == "old"
    assert not (final / "new.txt").exists()


def test_directory_transaction_no_overwrite_is_non_destructive(tmp_path: Path):
    final = tmp_path / "output"
    final.mkdir()
    (final / "old.txt").write_text("old", encoding="utf-8")
    transaction = DirectoryTransaction(final)
    transaction.prepare()
    (transaction.stage_for(final) / "new.txt").write_text("new", encoding="utf-8")

    with pytest.raises(FileExistsError):
        transaction.commit(overwrite=False)

    assert (final / "old.txt").read_text(encoding="utf-8") == "old"
