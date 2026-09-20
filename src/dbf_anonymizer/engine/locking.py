"""Cross-process destination writer exclusion for Phase 4 publication."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError

if sys.platform == "win32":
    import msvcrt

    def _acquire_os_lock(stream: BinaryIO) -> None:
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)

    def _release_os_lock(stream: BinaryIO) -> None:
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _acquire_os_lock(stream: BinaryIO) -> None:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _release_os_lock(stream: BinaryIO) -> None:
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


__all__ = ["DestinationLock"]


def _lock_failure(detail_code: str) -> PublicationError:
    return PublicationError(
        ErrorCode.PUBLICATION_FAILED,
        context=ErrorContext(operation="publication", detail_code=detail_code),
    )


class DestinationLock:
    """One real OS-owned exclusive lock for a normalized output identity.

    The lock file is a stable sibling of the destination.  Its existence is
    not ownership evidence: only the live kernel lock grants authority.  A
    process crash releases that authority while leaving transaction metadata
    and staging untouched for explicit stale-state detection.
    """

    __slots__ = ("_path", "_stream", "_locked")

    def __init__(self, path: Path) -> None:
        self._path = path
        self._stream: BinaryIO | None = None
        self._locked = False

    @property
    def path(self) -> Path:
        return self._path

    def __enter__(self) -> "DestinationLock":
        stream: BinaryIO | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            try:
                status = os.lstat(self._path)
            except FileNotFoundError:
                status = None
            if status is not None and not stat.S_ISREG(status.st_mode):
                raise _lock_failure("DESTINATION_LOCK_INVALID")
            stream = open(self._path, "a+b", buffering=0)
            opened = os.fstat(stream.fileno())
            current = os.lstat(self._path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _lock_failure("DESTINATION_LOCK_INVALID")
            if opened.st_size == 0:
                stream.write(b"\x00")
            stream.seek(0)
            self._acquire(stream)
        except PublicationError:
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass
            raise
        except OSError:
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass
            raise _lock_failure("DESTINATION_LOCK_UNAVAILABLE") from None
        self._stream = stream
        self._locked = True
        return self

    @staticmethod
    def _acquire(stream: BinaryIO) -> None:
        try:
            _acquire_os_lock(stream)
        except OSError:
            raise _lock_failure("DESTINATION_LOCK_HELD") from None

    @staticmethod
    def _release(stream: BinaryIO) -> None:
        stream.seek(0)
        _release_os_lock(stream)

    def close(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        failed = False
        orig_cause: BaseException | None = None
        try:
            if self._locked:
                self._release(stream)
        except OSError as exc:
            failed = True
            orig_cause = exc
        finally:
            self._locked = False
        try:
            stream.close()
        except OSError as exc:
            failed = True
            if orig_cause is None:
                orig_cause = exc
        if failed:
            raise _lock_failure("DESTINATION_LOCK_RELEASE_FAILED") from orig_cause

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except PublicationError as cleanup_failure:
            if exc_type is None:
                raise
            raise cleanup_failure from exc
