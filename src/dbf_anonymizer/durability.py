"""Platform-truthful durability primitives (REQ-P5-008).

This INTERNAL module is the ONE durability abstraction shared by the
transactional dataset publication (P4-009/P5-008) and the DATA_ONLY
transfer-bundle creation (REQ-P5-004..P5-007). It provides small, testable
primitives whose behavior is TRUTHFUL about the underlying platform:

* :func:`flush_stream` flushes a buffered stream handle.
* :func:`fsync_stream` performs ``os.fsync`` on the file descriptor -
  supported on POSIX and Windows for regular files.
* :func:`sync_directory` persists directory entries WHERE THE PLATFORM
  SUPPORTS IT. The three possible outcomes are strictly separated:

  - ``True``  — the directory entry was actually synced (POSIX and every
    other platform with a usable user-space directory-fsync primitive);
  - ``False`` — the platform genuinely does not support the primitive
    (Windows has no user-space directory-fsync primitive; on POSIX the
    canonical ``EINVAL`` reply reports "not supported for this
    file/filesystem"). The fact is reported truthfully: nothing was
    performed and callers must never claim a directory sync happened;
  - a typed :class:`~dbf_anonymizer.errors.PublicationError`
    (``PUBLICATION_INCOMPLETE``/``DURABILITY_DIRECTORY_SYNC_FAILED``) — a
    genuine, unexpected open/fsync I/O failure on a platform where the
    primitive IS supported. This is never silently downgraded to "not
    performed": an actual durability failure must surface and can never
    continue into a completed claim.

* :func:`atomic_replace` performs a same-filesystem atomic ``os.replace``
  and then persists the destination parent directory entry where the
  platform supports it; genuine durability failures propagate typed.
* :func:`write_durable_bytes` creates/replaces a regular file through ONE
  coherent crash-safe primitive: a same-directory temporary file receives
  the complete bytes, is flushed and fsynced, and only then atomically
  replaces the destination via ``os.replace``; the parent directory entry
  is persisted where the platform supports it. The previous valid content
  remains intact until the atomic replace and no temporary file remains on
  normal success (an orphaned temporary file can therefore only originate
  from an interrupted attempt and is classified deterministically by the
  crash-state reconciliation).
* :func:`fsync_tree` flushes+fsyncs every regular file under a directory
  and persists directory entries where supported, polling an optional
  cooperative checkpoint between regular files and between directories.

None of these primitives pretend an unsupported fsync happened; "where
available" from the immutable architecture is represented truthfully, and
a genuine durability failure is never conflated with an unsupported
primitive.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Callable

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError

__all__ = [
    "flush_stream",
    "fsync_stream",
    "sync_directory",
    "atomic_replace",
    "write_durable_bytes",
    "fsync_tree",
    "DURABILITY_OPERATION",
]

#: The private operation token carried by typed durability failures.
DURABILITY_OPERATION = "durability"

_WINDOWS_PLATFORM = os.name == "nt"


def _durability_failure(detail_code: str) -> PublicationError:
    """One typed, privacy-safe durability failure (no paths, no values)."""
    return PublicationError(
        ErrorCode.PUBLICATION_INCOMPLETE,
        context=ErrorContext(operation=DURABILITY_OPERATION, detail_code=detail_code),
    )


def flush_stream(stream: object) -> None:
    """Flush the buffered stream to the OS."""
    stream.flush()  # type: ignore[attr-defined]


def fsync_stream(stream: object) -> bool:
    """Flush AND fsync one open regular-file stream."""
    stream.flush()  # type: ignore[attr-defined]
    os.fsync(stream.fileno())  # type: ignore[attr-defined]
    return True


def sync_directory(path: Path) -> bool:
    """Persist a directory entry WHERE THE PLATFORM SUPPORTS IT.

    Returns:

    * ``True`` — the directory entry was actually synced.
    * ``False`` — the platform genuinely does not support the user-space
      directory-fsync primitive (Windows: directories cannot be opened for
      fsync; POSIX: the canonical ``EINVAL`` reply means the open
      file/filesystem does not support the primitive). Reported truthfully
      as NOT performed — never claimed, and never confused with a failure.

    Raises a typed
    :class:`~dbf_anonymizer.errors.PublicationError`
    (``DURABILITY_DIRECTORY_SYNC_FAILED``) for any other genuine open or
    fsync I/O failure — durability work must not silently continue into a
    completed claim.
    """
    try:
        descriptor = os.open(str(path), os.O_RDONLY)
    except PermissionError as error:
        if _WINDOWS_PLATFORM:
            # Documented platform limitation: a directory cannot be opened
            # for fsync on Windows — unsupported primitive, not a failure.
            return False
        raise _durability_failure("DURABILITY_DIRECTORY_SYNC_FAILED") from error
    except OSError as error:
        raise _durability_failure("DURABILITY_DIRECTORY_SYNC_FAILED") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno == errno.EINVAL:
            # Canonical "the primitive is not supported for this
            # file/filesystem" reply: reported truthfully as not performed.
            return False
        raise _durability_failure("DURABILITY_DIRECTORY_SYNC_FAILED") from error
    finally:
        os.close(descriptor)
    return True


def atomic_replace(source: Path, destination: Path) -> bool:
    """Atomically replace destination with source (same filesystem).

    The destination parent directory entry is persisted where the platform
    supports it; a genuine durability failure propagates as a typed
    durability failure instead of being silently downgraded.
    """
    os.replace(source, destination)
    return sync_directory(destination.parent)


def write_durable_bytes(path: Path, data: bytes) -> bool:
    """Durably create/replace a regular file with ONE crash-safe primitive.

    Sequence: a same-directory temporary file receives the COMPLETE bytes,
    is flushed and fsynced as a regular file, and only then atomically
    replaces the destination via ``os.replace``; the destination parent
    directory entry is persisted where the platform supports it. The
    previous valid content therefore remains intact until the atomic
    replace, and no temporary file remains on normal success. A genuine
    write/replace/fsync failure is typed and privacy-safe.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    try:
        with temporary.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        # Best-effort removal of the interrupted attempt's private
        # temporary file; the primary failure keeps its classification.
        try:
            temporary.unlink()
        except OSError:
            pass
        raise _durability_failure("DURABILITY_FILE_WRITE_FAILED") from error
    return sync_directory(path.parent)


def fsync_tree(
    directory: Path,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> int:
    """Flush + fsync every regular file under directory, then persist
    directory entries where supported. Returns the number of files fsynced.

    REQ-P1-008: the optional cooperative checkpoint is polled at bounded
    safe points — once before every regular file (i.e. between files) and
    once between every directory-entry persistence — so a long durability
    scan never becomes an uncancellable region. A genuine open/fsync I/O
    failure is a typed durability failure (never silently downgraded).
    """
    count = 0
    for current, _dirnames, files in os.walk(directory, followlinks=False):
        current_path = Path(current)
        for name in sorted(files):
            if checkpoint is not None:
                checkpoint()
            file_path = current_path / name
            try:
                descriptor = os.open(file_path, os.O_RDWR)
            except OSError as error:
                raise _durability_failure(
                    "DURABILITY_FILE_SYNC_FAILED"
                ) from error
            try:
                os.fsync(descriptor)
                count += 1
            except OSError as error:
                raise _durability_failure(
                    "DURABILITY_FILE_SYNC_FAILED"
                ) from error
            finally:
                os.close(descriptor)
    for current, dirnames, _files in os.walk(directory, followlinks=False, topdown=False):
        if checkpoint is not None:
            checkpoint()
        sync_directory(Path(current))
    if checkpoint is not None:
        checkpoint()
    sync_directory(directory)
    return count
