"""Obsługa strukturalnych indeksów CDX przez automatyzację Visual FoxPro."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class VfpError(RuntimeError):
    """Błąd otwarcia tabeli albo przebudowy CDX w Visual FoxPro."""


TABLE_FLAGS_OFFSET = 28
STRUCTURAL_CDX_FLAG = 0x01
MEMO_FILE_FLAG = 0x02
DATABASE_CONTAINER_FLAG = 0x04


@dataclass(frozen=True)
class VfpVerification:
    dbf: str
    records: int
    tag_count: int
    tags: tuple[str, ...]
    reindexed: bool


def companion_cdx(dbf_path: str | Path) -> Path | None:
    """Znajduje strukturalny CDX o tej samej nazwie bez względu na wielkość liter."""

    dbf = Path(dbf_path)
    if not dbf.parent.is_dir():
        return None
    expected = dbf.stem.casefold()
    for path in dbf.parent.iterdir():
        if (
            path.is_file()
            and path.suffix.casefold() == ".cdx"
            and path.stem.casefold() == expected
        ):
            return path
    return None


def dbf_has_structural_index(dbf_path: str | Path) -> bool:
    """Czy bit ``0x01`` flag tabeli VFP wskazuje na strukturalny CDX.

    Bajt 28 jest maską: ``0x01`` oznacza CDX, ``0x02`` FPT, a ``0x04`` DBC.
    Nie wolno sprawdzać całego bajtu jako wartości logicznej, bo tabela z samym
    memo ma wartość ``0x02`` i nie wymaga pliku CDX.
    """

    return bool(dbf_table_flags(dbf_path) & STRUCTURAL_CDX_FLAG)


def dbf_table_flags(dbf_path: str | Path) -> int:
    """Zwraca pełną maskę flag z bajtu 28 nagłówka DBF."""

    with Path(dbf_path).open("rb") as infile:
        header = infile.read(TABLE_FLAGS_OFFSET + 1)
    if len(header) <= TABLE_FLAGS_OFFSET:
        raise VfpError(
            f"[DBF_HEADER_TRUNCATED] Nagłówek DBF ma mniej niż "
            f"{TABLE_FLAGS_OFFSET + 1} bajtów: {dbf_path}"
        )
    return header[TABLE_FLAGS_OFFSET]


def validate_vfp_executable(executable: str | Path | None) -> Path | None:
    """Waliduje opcjonalną ścieżkę instalacji VFP podaną w konfiguracji."""

    if executable is None:
        return None
    path = Path(executable).expanduser().resolve()
    if not path.is_file():
        raise VfpError(
            f"[VFP_EXECUTABLE_MISSING] Nie istnieje skonfigurowany vfp9.exe: {path}"
        )
    return path


def rebuild_companion_cdx(
    source_dbf: str | Path,
    target_dbf: str | Path,
    *,
    progid: str = "VisualFoxPro.Application",
    timeout: int = 900,
) -> VfpVerification | None:
    """Kopiuje definicje CDX, wykonuje obowiązkowy REINDEX i sprawdza tagi."""

    source_cdx = companion_cdx(source_dbf)
    if source_cdx is None:
        return None
    target = Path(target_dbf)
    if not target.is_file():
        raise VfpError(f"[VFP_DBF_MISSING] Nie istnieje wynikowy DBF: {target}")
    target_cdx = target.with_suffix(source_cdx.suffix)
    shutil.copy2(source_cdx, target_cdx)
    try:
        result = _run_vfp(target, progid=progid, reindex=True, timeout=timeout)
    except BaseException:
        target_cdx.unlink(missing_ok=True)
        raise
    if result.tag_count <= 0:
        target_cdx.unlink(missing_ok=True)
        raise VfpError(
            f"[VFP_CDX_EMPTY] CDX nie zawiera tagów po REINDEX: {target_cdx}"
        )
    return result


def verify_vfp_open(
    dbf_path: str | Path,
    *,
    progid: str = "VisualFoxPro.Application",
    timeout: int = 300,
) -> VfpVerification:
    """Otwiera tabelę w VFP i odczytuje jej rekordy oraz tagi."""

    return _run_vfp(Path(dbf_path), progid=progid, reindex=False, timeout=timeout)


def _run_vfp(
    dbf_path: Path,
    *,
    progid: str,
    reindex: bool,
    timeout: int,
) -> VfpVerification:
    if os.name != "nt":
        raise VfpError(
            "[VFP_WINDOWS_REQUIRED] Obsługa CDX wymaga Windows i pełnego "
            "Visual FoxPro z zarejestrowanym serwerem COM"
        )

    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$vfp = $null
try {
    $vfp = New-Object -ComObject $env:DBF_ANON_VFP_PROGID
    $vfp.Visible = $false
    $dbf = $env:DBF_ANON_VFP_DBF
    $quoted = '"' + $dbf.Replace('"', '""') + '"'
    $vfp.DoCmd('SET SAFETY OFF')
    $vfp.DoCmd('SET EXCLUSIVE OFF')
    $vfp.DoCmd('CLOSE DATABASES ALL')
    $mode = if ($env:DBF_ANON_VFP_REINDEX -eq '1') { ' EXCLUSIVE' } else { ' SHARED' }
    $vfp.DoCmd('USE ' + $quoted + $mode + ' IN 0 ALIAS DBFANON')
    $vfp.DoCmd('SELECT DBFANON')
    $before = [int]$vfp.Eval('TAGCOUNT()')
    if ($env:DBF_ANON_VFP_REINDEX -eq '1') {
        if ($before -le 0) { throw 'Skopiowany CDX nie zawiera definicji tagów' }
        $vfp.DoCmd('REINDEX')
    }
    $after = [int]$vfp.Eval('TAGCOUNT()')
    $records = [int]$vfp.Eval('RECCOUNT()')
    $tags = @()
    for ($i = 1; $i -le $after; $i++) {
        $tag = [string]$vfp.Eval('TAG(' + $i + ')')
        if (-not [string]::IsNullOrWhiteSpace($tag)) {
            $tags += $tag
            $escapedTag = $tag.Replace(']', ']]')
            $vfp.DoCmd('SET ORDER TO TAG [' + $escapedTag + ']')
            $vfp.DoCmd('GO TOP')
        }
    }
    $vfp.DoCmd('SET ORDER TO 0')
    $vfp.DoCmd('USE IN DBFANON')
    [ordered]@{
        dbf = $dbf
        records = $records
        tag_count = $after
        tags = $tags
        reindexed = ($env:DBF_ANON_VFP_REINDEX -eq '1')
    } | ConvertTo-Json -Compress
}
catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
finally {
    if ($null -ne $vfp) {
        try { $vfp.DoCmd('CLOSE DATABASES ALL') } catch {}
        try { $vfp.Quit() } catch {}
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($vfp) | Out-Null
    }
}
'''
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    environment = os.environ.copy()
    environment.update(
        {
            "DBF_ANON_VFP_PROGID": progid,
            "DBF_ANON_VFP_DBF": str(dbf_path.resolve()),
            "DBF_ANON_VFP_REINDEX": "1" if reindex else "0",
        }
    )
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise VfpError(
            f"[VFP_AUTOMATION_FAILED] dbf={dbf_path} returncode="
            f"{completed.returncode} error={message}"
        )
    try:
        payload: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise VfpError(
            f"[VFP_INVALID_RESPONSE] dbf={dbf_path} output={completed.stdout!r}"
        ) from exc
    return VfpVerification(
        dbf=str(payload["dbf"]),
        records=int(payload["records"]),
        tag_count=int(payload["tag_count"]),
        tags=tuple(str(item) for item in payload.get("tags", [])),
        reindexed=bool(payload["reindexed"]),
    )
