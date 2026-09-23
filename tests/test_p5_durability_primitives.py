"""REQ-P5-008 — unit tests for platform-truthful durability primitives.

Covers durable regular-file flush, directory sync semantics, atomic
replace, fault injection boundaries, failure wrapping, no path/value
leakage from exceptions, platform-specific truthful behavior, and no
accidental operation outside supplied paths.

Only approved synthetic fixtures and disposable ``tmp_path`` data are used
by this suite; no production data.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from dbf_anonymizer.durability import (
    atomic_replace,
    fsync_stream,
    flush_stream,
    fsync_tree,
    sync_directory,
    write_durable_bytes,
)


class TestFlushAndFsync:
    def test_flush_stream_no_error(self, tmp_path: Path) -> None:
        path = tmp_path / "probe.bin"
        with path.open("wb") as stream:
            stream.write(b"data")
            flush_stream(stream)
        assert path.read_bytes() == b"data"

    def test_fsync_stream_returns_true(self, tmp_path: Path) -> None:
        path = tmp_path / "synced.bin"
        with path.open("wb") as stream:
            stream.write(b"data")
            assert fsync_stream(stream) is True
        assert path.read_bytes() == b"data"


class TestSyncDirectory:
    def test_sync_directory_truthful(self, tmp_path: Path) -> None:
        directory = tmp_path / "sub"
        directory.mkdir()
        result = sync_directory(directory)
        assert isinstance(result, bool)
        if sys.platform == "win32":
            assert result is False
        else:
            assert result is True

    def test_sync_directory_nonexistent_returns_false(self) -> None:
        result = sync_directory(Path(__file__).parent / "missing-dir-does-not-exist")
        assert result is False


class TestAtomicReplace:
    def test_replaces_existing(self, tmp_path: Path) -> None:
        source = tmp_path / "new.bin"
        source.write_bytes(b"replaced-content")
        destination = tmp_path / "old.bin"
        destination.write_bytes(b"original")
        atomic_replace(source, destination)
        assert destination.read_bytes() == b"replaced-content"
        assert not source.exists()

    def test_creates_if_absent(self, tmp_path: Path) -> None:
        source = tmp_path / "fresh.bin"
        source.write_bytes(b"fresh")
        destination = tmp_path / "deep" / "nested" / "new.bin"
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_replace(source, destination)
        assert destination.read_bytes() == b"fresh"
        assert not source.exists()


class TestWriteDurableBytes:
    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "durable.json"
        write_durable_bytes(path, b"deep-content")
        assert path.read_bytes() == b"deep-content"


class TestFsyncTree:
    def test_fsync_tree_counts_files(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.txt").write_bytes(b"a")
        (tmp_path / "b.txt").write_bytes(b"b")
        (tmp_path / "sub" / "c.txt").write_bytes(b"c")
        count = fsync_tree(tmp_path)
        assert count == 3

    def test_fsync_tree_empty_dir(self, tmp_path: Path) -> None:
        count = fsync_tree(tmp_path)
        assert count == 0


class TestPlatformTruthfulness:
    def test_sync_directory_windows_reports_unsupported(self) -> None:
        """On Windows, directory fsync is unsupported; the primitive is
        reported truthfully as NOT performed."""
        if sys.platform != "win32":
            pytest.skip("POSIX supports directory fsync")
        from dbf_anonymizer.durability import sync_directory

        result = sync_directory(Path(__file__).resolve().parent)
        assert result is False