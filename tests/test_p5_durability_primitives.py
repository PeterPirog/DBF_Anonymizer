"""REQ-P5-008 — unit tests for platform-truthful durability primitives.

Covers durable regular-file flush, directory sync semantics, atomic
replace, crash-safe crash-state replacement (previous content intact until
the atomic replace, no temporary residue on success), fault injection
boundaries, typed failure propagation (genuine durability failures are
never silently downgraded), cooperative cancellation checkpoints between
files/directories, failure wrapping, no path/value leakage from exceptions,
platform-specific truthful behavior, and no accidental operation outside
supplied paths.

Only approved synthetic fixtures and disposable ``tmp_path`` data are used
by this suite; no production data.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

import dbf_anonymizer.durability as durability_module
from dbf_anonymizer.durability import (
    PostRenameDurabilityError,
    atomic_replace,
    fsync_stream,
    flush_stream,
    fsync_tree,
    sync_directory,
    write_durable_bytes,
)
from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError


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

    def test_sync_directory_missing_directory_is_a_typed_failure(self) -> None:
        """A missing directory is a GENUINE open I/O failure, not an
        unsupported primitive: it surfaces typed (never silently downgraded
        to a completed claim) on every platform."""
        from dbf_anonymizer.errors import ErrorCode, PublicationError

        with pytest.raises(PublicationError) as excinfo:
            sync_directory(
                Path(__file__).parent / "missing-dir-does-not-exist"
            )
        assert excinfo.value.code is ErrorCode.PUBLICATION_INCOMPLETE
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED"
        )


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

    def test_success_leaves_no_temporary_file(self, tmp_path: Path) -> None:
        """REQ-P5-008 defect A: the atomic crash-state replacement leaves no
        temporary transaction file on normal success."""
        path = tmp_path / "transaction.json"
        write_durable_bytes(path, b"first")
        write_durable_bytes(path, b"second")
        assert path.read_bytes() == b"second"
        assert [entry.name for entry in tmp_path.iterdir()] == ["transaction.json"]

    def test_previous_content_intact_until_atomic_replace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failure during the atomic replace (the simulated crash window)
        leaves the previous valid transaction state intact."""
        path = tmp_path / "transaction.json"
        write_durable_bytes(path, b"previous-valid-state")
        real_replace = os.replace

        def interrupted_replace(source: object, destination: object) -> None:
            if Path(str(destination)) == path:
                raise OSError("simulated crash during replace")
            real_replace(source, destination)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "replace", interrupted_replace)
        with pytest.raises(PublicationError) as excinfo:
            write_durable_bytes(path, b"replacement-state")
        assert excinfo.value.context.detail_code == "DURABILITY_FILE_WRITE_FAILED"
        # The previous valid state survived the interrupted replacement.
        assert path.read_bytes() == b"previous-valid-state"
        # A HANDLED failure never leaves private temporary residue either.
        assert [entry.name for entry in tmp_path.iterdir()] == ["transaction.json"]

    def test_write_failure_keeps_previous_content(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failure while writing/fsyncing the temporary file leaves the
        previous valid content untouched (fail-closed crash-state update)."""
        path = tmp_path / "transaction.json"
        write_durable_bytes(path, b"previous-valid-state")
        def failing_fsync(fd: object) -> None:
            raise OSError(errno.EIO, "simulated fsync failure")

        monkeypatch.setattr(os, "fsync", failing_fsync)
        with pytest.raises(PublicationError) as excinfo:
            write_durable_bytes(path, b"replacement")
        assert excinfo.value.context.detail_code == "DURABILITY_FILE_WRITE_FAILED"
        assert path.read_bytes() == b"previous-valid-state"
        assert [entry.name for entry in tmp_path.iterdir()] == ["transaction.json"]

    def test_no_path_or_value_leakage_in_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "PRIVATE-canary-name.json"
        write_durable_bytes(path, b"PREVIOUS-PRIVATE-STATE")
        real_replace = os.replace

        def failing_replace(source: object, destination: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", failing_replace)
        with pytest.raises(PublicationError) as excinfo:
            write_durable_bytes(path, b"NEW-PRIVATE-STATE")
        serialized = repr(excinfo.value.to_dict())
        assert "PRIVATE-canary-name" not in serialized
        assert "NEW-PRIVATE-STATE" not in serialized
        assert "PREVIOUS-PRIVATE-STATE" not in serialized
        assert str(tmp_path) not in serialized


class TestGenuineDurabilityFailuresAreTyped:
    """Defect B: genuine I/O failures are NEVER silently downgraded to
    'not performed' or to a completed claim; unsupported primitives are
    never confused with failures."""

    def test_missing_directory_open_failure_is_typed(self) -> None:
        with pytest.raises(PublicationError) as excinfo:
            sync_directory(Path(__file__).parent / "missing-dir-does-not-exist")
        assert excinfo.value.code is ErrorCode.PUBLICATION_INCOMPLETE
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED"
        )

    def test_fsync_open_failure_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def failing_open(path: object, *flags: object) -> int:
            raise FileNotFoundError(errno.ENOENT, "simulated open failure")

        monkeypatch.setattr(os, "open", failing_open)
        with pytest.raises(PublicationError) as excinfo:
            sync_directory(tmp_path)
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED"
        )

    def test_fsync_directory_genuine_failure_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if sys.platform == "win32":
            pytest.skip("Windows cannot open directories for fsync at all")
        def failing_fsync(fd: object) -> None:
            raise OSError(errno.EIO, "simulated directory fsync failure")

        monkeypatch.setattr(os, "fsync", failing_fsync)
        with pytest.raises(PublicationError) as excinfo:
            sync_directory(tmp_path)
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED"
        )

    def test_fsync_einval_is_reported_as_unsupported_not_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if sys.platform == "win32":
            pytest.skip("Windows cannot open directories for fsync at all")

        def einval_fsync(fd: object) -> None:
            raise OSError(errno.EINVAL, "primitive not supported here")

        monkeypatch.setattr(os, "fsync", einval_fsync)
        assert sync_directory(tmp_path) is False

    def test_atomic_replace_propagates_directory_sync_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def failing_open(path: object, *flags: object) -> int:
            raise FileNotFoundError(errno.ENOENT, "simulated open failure")

        monkeypatch.setattr(os, "open", failing_open)
        source = tmp_path / "new.bin"
        source.write_bytes(b"moved")
        destination = tmp_path / "deep" / "target.bin"
        destination.parent.mkdir(parents=True, exist_ok=True)
        with pytest.raises(PostRenameDurabilityError) as excinfo:
            atomic_replace(source, destination)
        # The typed failure carries the OBJECTIVE rename fact: the rename
        # already happened, so this is never "nothing was promoted".
        assert excinfo.value.renamed is True
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED_AFTER_RENAME"
        )
        # The replace itself still happened; only the durability failure
        # surfaced typed.
        assert destination.read_bytes() == b"moved"
        assert not source.exists()

    def test_post_rename_sync_failure_wraps_the_typed_sync_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The post-rename wrapper chains the underlying typed directory-sync
        failure (typed boundary, no raw exception escape)."""
        def failing_sync(path: object) -> bool:
            raise PublicationError(
                ErrorCode.PUBLICATION_INCOMPLETE,
                context=ErrorContext(
                    operation="durability",
                    detail_code="DURABILITY_DIRECTORY_SYNC_FAILED",
                ),
            )

        monkeypatch.setattr(durability_module, "sync_directory", failing_sync)
        source = tmp_path / "moved.bin"
        source.write_bytes(b"payload")
        destination = tmp_path / "target.bin"
        with pytest.raises(PostRenameDurabilityError) as excinfo:
            atomic_replace(source, destination)
        assert excinfo.value.renamed is True
        assert excinfo.value.context.detail_code == (
            "DURABILITY_DIRECTORY_SYNC_FAILED_AFTER_RENAME"
        )
        assert destination.read_bytes() == b"payload"
        assert not source.exists()

    def test_replace_failure_carries_no_rename_fact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Boundary B: a failure OF os.replace itself means the rename did
        NOT happen (the primitive is atomic) — no rename fact may be
        manufactured."""
        def failing_replace(source: object, destination: object) -> None:
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", failing_replace)
        source = tmp_path / "kept.bin"
        source.write_bytes(b"intact")
        destination = tmp_path / "target.bin"
        with pytest.raises(OSError):
            atomic_replace(source, destination)
        assert source.read_bytes() == b"intact"
        assert not destination.exists()

    def test_fsync_tree_regular_file_failure_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "a.txt").write_bytes(b"a")
        (tmp_path / "b.txt").write_bytes(b"b")
        def failing_fsync(fd: object) -> None:
            raise OSError(errno.EIO, "simulated file fsync failure")

        monkeypatch.setattr(os, "fsync", failing_fsync)
        with pytest.raises(PublicationError) as excinfo:
            fsync_tree(tmp_path)
        assert excinfo.value.context.detail_code == (
            "DURABILITY_FILE_SYNC_FAILED"
        )


class TestFsyncTreeCooperativeCheckpoints:
    """REQ-P1-008: durability scanning is never an uncancellable region."""

    def test_checkpoint_polled_between_files_and_directories(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "deeper").mkdir()
        (tmp_path / "a.txt").write_bytes(b"a")
        (tmp_path / "b.txt").write_bytes(b"b")
        (tmp_path / "sub" / "c.txt").write_bytes(b"c")
        polls: list[int] = []

        def checkpoint() -> None:
            polls.append(len(polls))

        count = fsync_tree(tmp_path, checkpoint=checkpoint)
        assert count == 3
        # Files: 3 polls; bottom-up directory entries (sub/deeper, sub,
        # tmp_path) + the final root entry: 4 polls.
        assert len(polls) == 7

    def test_checkpoint_cancellation_propagates_typed(
        self, tmp_path: Path
    ) -> None:
        from dbf_anonymizer import CancellationError
        from dbf_anonymizer.errors import ErrorCode, ErrorContext

        (tmp_path / "a.txt").write_bytes(b"a")
        (tmp_path / "b.txt").write_bytes(b"b")

        def cancel_on_first_file() -> None:
            raise CancellationError(
                ErrorCode.OPERATION_CANCELLED,
                context=ErrorContext(
                    operation="probe", detail_code="CANCELLED_BY_CHECK"
                ),
            )

        with pytest.raises(CancellationError):
            fsync_tree(tmp_path, checkpoint=cancel_on_first_file)


class TestPlatformTruthfulness:
    def test_sync_directory_windows_reports_unsupported(self) -> None:
        """On Windows, directory fsync is unsupported; the primitive is
        reported truthfully as NOT performed."""
        if sys.platform != "win32":
            pytest.skip("POSIX supports directory fsync")
        from dbf_anonymizer.durability import sync_directory

        result = sync_directory(Path(__file__).resolve().parent)
        assert result is False