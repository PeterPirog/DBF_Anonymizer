"""Minimalna, bezpieczna obsługa lokalnego pliku ``.env``.

Plik jest opcjonalny. Zmienne ustawione przez PowerShell mają pierwszeństwo przed
wartościami z pliku, a wartości nie podlegają wykonywaniu ani interpolacji.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_env_file(path: str | Path | None = None) -> Path | None:
    """Wczytuje ``.env`` z bieżącego katalogu bez nadpisywania środowiska."""

    candidate = Path(path) if path is not None else Path.cwd() / ".env"
    if not candidate.is_file():
        return None
    for line_number, raw_line in enumerate(
        candidate.read_text(encoding="utf-8-sig").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(
                f"[ENV_INVALID_LINE] path={candidate} line={line_number}"
            )
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not _ENV_NAME.fullmatch(name):
            raise ValueError(
                f"[ENV_INVALID_NAME] path={candidate} line={line_number} name={name!r}"
            )
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(name, value)
    return candidate.resolve()


def env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value) if value else None


def env_text(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def env_int(name: str, default: int, *, minimum: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"[ENV_INVALID_INTEGER] name={name} value={value!r}") from exc
    if parsed < minimum:
        raise ValueError(
            f"[ENV_INTEGER_OUT_OF_RANGE] name={name} value={parsed} minimum={minimum}"
        )
    return parsed


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on", "tak"}:
        return True
    if normalized in {"0", "false", "no", "off", "nie"}:
        return False
    raise ValueError(f"[ENV_INVALID_BOOLEAN] name={name} value={value!r}")


def env_list(name: str) -> list[str]:
    """Zwraca listę rozdzielaną średnikami (bez konfliktu z ``C:\\...``)."""

    return [item.strip() for item in os.environ.get(name, "").split(";") if item.strip()]
