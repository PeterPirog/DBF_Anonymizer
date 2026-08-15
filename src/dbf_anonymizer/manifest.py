"""Manifest kompletności i integralności opublikowanego katalogu."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MANIFEST_FILENAME = "dbf_anonymizer_manifest.json"


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as infile:
        while chunk := infile.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    root: str | Path,
    *,
    operation: str,
    source: str | Path,
    tables: list[dict[str, Any]],
    dictionary_sha256: str | None = None,
    excluded_tables: list[dict[str, str]] | None = None,
) -> Path:
    target_root = Path(root)
    artifacts: list[dict[str, Any]] = []
    for path in sorted(target_root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not path.is_file() or path.name == MANIFEST_FILENAME:
            continue
        if path.suffix.casefold() not in {".dbf", ".fpt", ".cdx"}:
            continue
        artifacts.append(
            {
                "path": path.relative_to(target_root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    payload = {
        "format": 1,
        "operation": operation,
        "source": str(Path(source).resolve()),
        "dictionary_sha256": dictionary_sha256,
        "tables": tables,
        "excluded_tables": excluded_tables or [],
        "artifacts": artifacts,
    }
    path = target_root / MANIFEST_FILENAME
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path
