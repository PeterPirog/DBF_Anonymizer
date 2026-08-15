"""Wielokatalogowa publikacja wyniku z możliwością wycofania."""
from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class _DirectoryEntry:
    final: Path
    stage: Path
    backup: Path
    committed: bool = False
    had_previous: bool = False


class DirectoryTransaction:
    """Buduje katalogi obok celu i publikuje je dopiero po pełnym sukcesie."""

    def __init__(self, *final_paths: str | Path) -> None:
        token = f"{os.getpid()}-{uuid.uuid4().hex[:10]}"
        self.entries: list[_DirectoryEntry] = []
        for value in final_paths:
            final = Path(value).resolve()
            stage = final.with_name(f".{final.name}.build-{token}")
            backup = final.with_name(f".{final.name}.backup-{token}")
            self.entries.append(_DirectoryEntry(final, stage, backup))

    def stage_for(self, final_path: str | Path) -> Path:
        final = Path(final_path).resolve()
        for entry in self.entries:
            if entry.final == final:
                return entry.stage
        raise KeyError(final)

    def prepare(self) -> None:
        for entry in self.entries:
            shutil.rmtree(entry.stage, ignore_errors=True)
            shutil.rmtree(entry.backup, ignore_errors=True)
            entry.stage.parent.mkdir(parents=True, exist_ok=True)
            entry.stage.mkdir(parents=True)

    def commit(self, *, overwrite: bool) -> None:
        """Publikuje wszystkie katalogi albo przywraca poprzednie wersje."""

        try:
            for entry in self.entries:
                if entry.final.exists():
                    if not overwrite:
                        raise FileExistsError(
                            f"Katalog wynikowy już istnieje: {entry.final}"
                        )
                    entry.had_previous = True
                    os.replace(entry.final, entry.backup)
                os.replace(entry.stage, entry.final)
                entry.committed = True
        except BaseException:
            self._rollback()
            raise
        else:
            for entry in self.entries:
                shutil.rmtree(entry.backup, ignore_errors=True)

    def abort(self) -> None:
        for entry in self.entries:
            shutil.rmtree(entry.stage, ignore_errors=True)
            if entry.backup.exists() and not entry.final.exists():
                os.replace(entry.backup, entry.final)

    def _rollback(self) -> None:
        for entry in reversed(self.entries):
            if entry.committed and entry.final.exists():
                shutil.rmtree(entry.final, ignore_errors=True)
            if entry.backup.exists():
                os.replace(entry.backup, entry.final)
            shutil.rmtree(entry.stage, ignore_errors=True)
