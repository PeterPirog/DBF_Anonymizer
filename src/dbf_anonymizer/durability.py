"""Platform-truthful durability primitives (REQ-P5-008).

This INTERNAL module is the ONE durability abstraction shared by the
transactional dataset publication (P4-009/P5-008) and the DATA_ONLY
transfer-bundle creation (REQ-P5-004..P5-007). It provides small, testable
primitives whose behavior is TRUTHFUL about the underlying platform:

* :func:`flush_stream` flushes a buffered stream handle.
* :func:`fsync_stream` performs ``os.fsync`` on the file descriptor -
  supported on POSIX and Windows for regular files.
* :func:`sync_directory` persists directory entries WHERE THE PLATFORM
  SUPPORTS IT (POSIX: open+fsync on the directory fd; Windows: no
  user-space directory-fsync primitive exists). It returns ``True`` when
  the directory was actually synced and ``False`` when the platform does
  not support the primitive - callers must never claim a directory sync
  happened when it did not.
* :func:`atomic_replace` performs a same-filesystem atomic ``os.replace``
  and then persists the destination parent directory entry where the
  platform supports it.

None of these primitives pretend an unsupported fsync happened; "where
available" from the immutable architecture is represented truthfully.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO, Callable

__all__ = [
    "flush_stream",
    "fsync_stream",
    "sync_directory",
    "atomic_replace",
    "write_durable_bytes",
    "fsync_tree",
]


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

    POSIX: the directory is opened read-only and ``os.fsync`` is applied to
    the directory descriptor.
    Windows: user-space directory fsync is not supported; the primitive is
    reported truthfully as NOT performed (``False``).
    """
    try:
        descriptor = os.open(str(path), os.O_RDONLY)
    except OSError:
        return False
    try:
        os.fsync(descriptor)
        return True
    except OSError:
        return False
    finally:
        os.close(descriptor)


def atomic_replace(source: Path, destination: Path) -> bool:
    """Atomically replace destination with source (same filesystem)."""
    os.replace(source, destination)
    return sync_directory(destination.parent)


def write_durable_bytes(path: Path, data: bytes) -> bool:
    """Write data durably: create/replace, flush, fsync, sync parent dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return sync_directory(path.parent)


def fsync_tree(directory: Path) -> int:
    """Flush + fsync every regular file under directory, then persist
    directory entries where supported. Returns the number of files fsynced."""
    count = 0
    for current, _dirnames, files in os.walk(directory, followlinks=False):
        current_path = Path(current)
        for name in sorted(files):
            file_path = current_path / name
            descriptor = os.open(file_path, os.O_RDWR)
            try:
                os.fsync(descriptor)
                count += 1
            finally:
                os.close(descriptor)
    for current, dirnames, _files in os.walk(directory, followlinks=False, topdown=False):
        sync_directory(Path(current))
    sync_directory(directory)
    return count