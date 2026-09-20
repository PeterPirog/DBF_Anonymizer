"""Cross-process destination writer exclusion for Phase 4 publication."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError

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
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            try:
                status = os.lstat(self._path)
            except FileNotFoundError:
                status = None
            if status is not None and not stat.S_ISREG(status.st_mode):
                raise _lock_failure("DESTINATION_LOCK_INVALID")
            stream = open(self._path, "a+b", buffering=0)
            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"\x00")
            stream.seek(0)
            self._acquire(stream)
        except PublicationError:
            raise
        except (OSError, ImportError):
            raise _lock_failure("DESTINATION_LOCK_UNAVAILABLE") from None
        self._stream = stream
        self._locked = True
        return self

    @staticmethod
    def _acquire(stream: BinaryIO) -> None:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    stream.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
        except OSError:
            stream.close()
            raise _lock_failure("DESTINATION_LOCK_HELD") from None

    @staticmethod
    def _release(stream: BinaryIO) -> None:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(  # type: ignore[attr-defined]
                stream.fileno(), fcntl.LOCK_UN  # type: ignore[attr-defined]
            )

    def close(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        failed = False
        try:
            if self._locked:
                self._release(stream)
        except (OSError, ImportError):
            failed = True
        finally:
            self._locked = False
            try:
                stream.close()
            except OSError:
                failed = True
        if failed:
            raise _lock_failure("DESTINATION_LOCK_RELEASE_FAILED")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except PublicationError:
            if exc_type is None:
                raise
