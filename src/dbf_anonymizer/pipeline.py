"""Wysokiepoziomowy pipeline anonimizacji katalogów DBF.

Trzy operacje główne:
- anonymize_directory(source_dir, ...) → katalog ``<source>_anonymized`` + słowniki
- make_dbf_recovery(anonymized_dir, dictionary_dir) → katalog ``<anonymized>_recovered``
- self_test(source_dir) → weryfikacja round-trip: źródłowy DBF == zrekonstruowany DBF

Przepływ anonimizacji (per tabela DBF w katalogu):
    DBF źródłowy
      → export_dbf (dbfbridge) → pośredni JSONL + _schema.json
      → anonymize_records (usunięcie __dbfbridge_raw_record__, transformacja pól)
      → zapis zaanonimizowanego JSONL
      → reconstruct_dbf (dbfbridge) → DBF zaanonimizowany
      → save_dictionary (słownik oryginał↔anonim)

Przepływ recovery (per tabela):
    DBF zaanonimizowany
      → export_dbf → pośredni JSONL + _schema.json
      → recover_records (przywrócenie oryginalnych wartości ze słownika)
      → zapis zrekonstruowanego JSONL
      → reconstruct_dbf → DBF zrekonstruowany

Self-test wykonuje pełny round-trip i porównuje kanonicznie źródłowy DBF
z zrekonstruowanym DBF (wartości pól + liczba rekordów + kolejność).
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dbfbridge import export_dbf, reconstruct_dbf

from .anonymizer import AnonymizeOptions, anonymize_records, recover_records
from .dictionary import (
    TableDict,
    dictionary_filename,
    load_dictionary,
    save_dictionary,
)
from .schema import load_schema


# ---------------------------------------------------------------------------
# Typy wyników
# ---------------------------------------------------------------------------

@dataclass
class TableOutcome:
    """Wynik operacji dla jednej tabeli."""
    table: str               # nazwa pliku DBF (np. "bok.dbf")
    relative_path: str       # ścieżka względem źródła
    status: str = "OK"       # OK / WARNING / FAILED
    records: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class AnonymizeResult:
    """Wynik anonymize_directory."""
    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(1 for t in self.tables if t.status == "OK")

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tables if t.status == "FAILED")

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Anonimizacja nie powiodła się dla {self.failed} tabel.")


@dataclass
class RecoveryResult:
    """Wynik make_dbf_recovery."""
    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(1 for t in self.tables if t.status == "OK")

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tables if t.status == "FAILED")

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Recovery nie powiodło się dla {self.failed} tabel.")


@dataclass
class SelfTestReport:
    """Wynik self_test — porównanie źródłowego vs zrekonstruowanego DBF."""
    source: Path
    anonymized: Path
    recovered: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    canonical_matches: int = 0
    canonical_mismatches: int = 0
    exit_code: int = 0

    @property
    def successful(self) -> bool:
        return self.exit_code == 0


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------

def _iter_dbf_files(root: Path) -> list[Path]:
    """Rekursywnie znajduje pliki .dbf z danymi (pomija formularze VFP)."""
    skip_suffixes = {".scx", ".sct", ".frx", ".frt", ".lbx", ".lbt",
                     ".mnx", ".mnt", ".pjx", ".pjt", ".vcx", ".vct",
                     ".dbc", ".dct", ".dcx", ".prg"}
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() != ".dbf":
            continue
        # Formularze VFP mają odpowiadające pliki .sct/.scx — pomijamy je.
        # Heurystyka: jeśli obok jest plik z tym samym stem i rozszerzeniem
        # z skip_suffixes, traktuj jako formularz.
        stem = path.stem.lower()
        parent = path.parent
        if any((parent / f"{stem}{ext}").exists() for ext in skip_suffixes):
            continue
        found.append(path)
    return found


def _relative_to(path: Path, root: Path) -> Path:
    """Ścieżka względem root (POSIX-style dla spójności ze schematem)."""
    return path.resolve().relative_to(root.resolve())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Wczytuje wszystkie rekordy z pliku JSONL (pomija puste linie)."""
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as infile:
        for line in infile:
            stripped = line.strip()
            if not stripped:
                continue
            records.append(json.loads(stripped))
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Zapisuje rekordy do pliku JSONL (po jednym na linię, compact JSON)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as outfile:
        for rec in records:
            outfile.write(json.dumps(rec, ensure_ascii=False, allow_nan=False,
                                     separators=(",", ":")))
            outfile.write("\n")
    tmp.replace(path)


def _schema_path_for_jsonl(jsonl_path: Path) -> Path:
    """Zwraca ścieżkę _schema.json obok pliku JSONL."""
    return jsonl_path.with_name(f"{jsonl_path.stem}_schema.json")


def _default_output_dir(source: Path, suffix: str) -> Path:
    """<source>_anonymized lub <source>_recovered."""
    return source.parent / f"{source.name}{suffix}"


# ---------------------------------------------------------------------------
# Anonimizacja katalogu
# ---------------------------------------------------------------------------

def anonymize_directory(
    source_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    dictionary_dir: str | Path | None = None,
    memo_mode: str = "mask",
    date_offset_days: int = 0,
    salt: str = "",
    overwrite: bool = True,
    keep_temp: bool = False,
) -> AnonymizeResult:
    """Anonimizuje wszystkie pliki DBF w katalogu źródłowym.

    Tworzy katalog wyjściowy z identyczną strukturą plików DBF, ale z
    zaanonimizowanymi danymi. Zapisuje słowniki (po jednym per tabela) w
    ``dictionary_dir``.

    Args:
        source_dir: katalog źródłowy z plikami DBF.
        output_dir: katalog wyjściowy (domyślnie ``<source>_anonymized``).
        dictionary_dir: katalog słowników (domyślnie ``<output>_dict``).
        memo_mode: 'mask' (pola M/G → 'MEMO') lub 'keep' (bez zmian).
        date_offset_days: stały offset dni dla D/T (0 = bez zmian).
        salt: sól dla deterministycznego maskowania pól C.
        overwrite: nadpisz istniejące pliki wyjściowe.
        keep_temp: zachowaj pośrednie JSONL w ``var/`` (debug).

    Returns:
        AnonymizeResult z wynikiem per tabela.
    """
    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")

    output = Path(output_dir).resolve() if output_dir else _default_output_dir(source, "_anonymized")
    dict_dir = Path(dictionary_dir).resolve() if dictionary_dir else _default_output_dir(source, "_dict")
    temp_root = source.parent / "var" / f"{source.name}_anon_temp"
    if temp_root.exists():
        shutil.rmtree(temp_root, ignore_errors=True)

    if output.exists() and overwrite:
        shutil.rmtree(output, ignore_errors=True)
    if dict_dir.exists() and overwrite:
        shutil.rmtree(dict_dir, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    dict_dir.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    options = AnonymizeOptions(
        memo_mode=memo_mode,
        date_offset_days=date_offset_days,
        salt=salt,
    )

    dbf_files = _iter_dbf_files(source)
    result = AnonymizeResult(source=source, output=output, dictionary_dir=dict_dir)
    if not dbf_files:
        no_tables = TableOutcome(table="-", relative_path="-", status="WARNING")
        no_tables.warnings.append("Brak plików DBF z danymi w katalogu źródłowym.")
        result.tables.append(no_tables)
        result.exit_code = 2
        return result

    for dbf_path in dbf_files:
        rel = _relative_to(dbf_path, source)
        outcome = TableOutcome(table=dbf_path.name, relative_path=rel.as_posix())
        try:
            _anonymize_one_table(
                dbf_path=dbf_path,
                relative=rel,
                source_root=source,
                output_root=output,
                dict_dir=dict_dir,
                temp_root=temp_root,
                options=options,
                overwrite=overwrite,
                keep_temp=keep_temp,
                outcome=outcome,
            )
        except Exception as exc:  # noqa: BLE001
            outcome.status = "FAILED"
            outcome.errors.append(f"{dbf_path.name}: {exc}")
        result.tables.append(outcome)
        if outcome.status == "FAILED":
            result.exit_code = 1
        elif outcome.status == "WARNING" and result.exit_code == 0:
            result.exit_code = 2

    if not keep_temp:
        shutil.rmtree(temp_root, ignore_errors=True)
    return result


def _anonymize_one_table(
    *,
    dbf_path: Path,
    relative: Path,
    source_root: Path,
    output_root: Path,
    dict_dir: Path,
    temp_root: Path,
    options: AnonymizeOptions,
    overwrite: bool,
    keep_temp: bool,
    outcome: TableOutcome,
) -> None:
    """Anonimizuje jedną tabelę DBF: export → anonymize → reconstruct."""
    rel_posix = relative.as_posix()
    # 1. Eksport źródła do JSONL (z memo inline, deleted include)
    src_temp = temp_root / "source" / relative.parent
    src_temp.mkdir(parents=True, exist_ok=True)
    export_dbf(
        source=dbf_path,
        output=src_temp,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )
    jsonl_name = relative.with_suffix(".jsonl").name
    src_jsonl = src_temp / jsonl_name
    src_schema = _schema_path_for_jsonl(src_jsonl)
    if not src_jsonl.is_file():
        raise FileNotFoundError(f"Eksport nie wygenerował JSONL: {src_jsonl}")

    # 2. Wczytaj schemat i rekordy
    schema = load_schema(src_schema)
    records = _read_jsonl(src_jsonl)
    data_records = [r for r in records if r.get("type") not in ("summary", "table")]
    outcome.records = len(data_records)

    # 3. Anonimizuj
    anonymized_records, table_dict = anonymize_records(schema, records, options)

    # 4. Zapisz zaanonimizowany JSONL + skopiuj schemat (niezmieniony)
    anon_temp = temp_root / "anonymized" / relative.parent
    anon_temp.mkdir(parents=True, exist_ok=True)
    anon_jsonl = anon_temp / jsonl_name
    anon_schema = _schema_path_for_jsonl(anon_jsonl)
    _write_jsonl(anon_jsonl, anonymized_records)
    shutil.copyfile(src_schema, anon_schema)

    # 5. Reconstruct DBF z zaanonimizowanego JSONL
    out_dbf = output_root / relative
    out_dbf.parent.mkdir(parents=True, exist_ok=True)
    # reconstruct_dbf tworzy .dbf (i .fpt jeśli memo) z katalogu zawierającego
    # JSONL + _schema.json. Dlatego wskazujemy katalog anon_temp.
    recon = reconstruct_dbf(
        source=anon_temp,
        output=out_dbf.parent,
        input_format="jsonl",
        memo="inline",
        overwrite=True,
    )
    # Sprawdź wynik reconstruct
    for r in recon.results:
        if r.status == "FAILED":
            outcome.status = "FAILED"
            outcome.errors.extend(r.errors or [f"reconstruct FAILED: {r.source}"])
            return
        if r.warnings:
            outcome.warnings.extend(r.warnings)

    # 6. Zapisz słownik
    table_dict.table = dbf_path.name
    table_dict.relative_path = rel_posix
    save_dictionary(table_dict, dict_dir)

    if outcome.errors:
        outcome.status = "FAILED"
    elif outcome.warnings:
        outcome.status = "WARNING"
    else:
        outcome.status = "OK"


# ---------------------------------------------------------------------------
# Recovery katalogu
# ---------------------------------------------------------------------------

def make_dbf_recovery(
    anonymized_dir: str | Path,
    dictionary_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    overwrite: bool = True,
    keep_temp: bool = False,
) -> RecoveryResult:
    """Odtwarza pierwotne dane DBF z katalogu zaanonimizowanego + słowników.

    Args:
        anonymized_dir: katalog z zaanonimizowanymi plikami DBF.
        dictionary_dir: katalog ze słownikami (dictionary_*.json).
        output_dir: katalog wyjściowy (domyślnie ``<anonymized>_recovered``).
        overwrite: nadpisz istniejące pliki wyjściowe.
        keep_temp: zachowaj pośrednie JSONL.

    Returns:
        RecoveryResult z wynikiem per tabela.
    """
    source = Path(anonymized_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog zaanonimizowany nie istnieje: {source}")
    dict_dir = Path(dictionary_dir).resolve()
    if not dict_dir.is_dir():
        raise FileNotFoundError(f"Katalog słowników nie istnieje: {dict_dir}")

    output = Path(output_dir).resolve() if output_dir else _default_output_dir(source, "_recovered")
    temp_root = source.parent / "var" / f"{source.name}_recover_temp"
    if temp_root.exists():
        shutil.rmtree(temp_root, ignore_errors=True)

    if output.exists() and overwrite:
        shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    dbf_files = _iter_dbf_files(source)
    result = RecoveryResult(source=source, output=output, dictionary_dir=dict_dir)
    if not dbf_files:
        return result

    for dbf_path in dbf_files:
        rel = _relative_to(dbf_path, source)
        outcome = TableOutcome(table=dbf_path.name, relative_path=rel.as_posix())
        try:
            _recover_one_table(
                dbf_path=dbf_path,
                relative=rel,
                source_root=source,
                output_root=output,
                dict_dir=dict_dir,
                temp_root=temp_root,
                overwrite=overwrite,
                keep_temp=keep_temp,
                outcome=outcome,
            )
        except Exception as exc:  # noqa: BLE001
            outcome.status = "FAILED"
            outcome.errors.append(f"{dbf_path.name}: {exc}")
        result.tables.append(outcome)
        if outcome.status == "FAILED":
            result.exit_code = 1
        elif outcome.status == "WARNING" and result.exit_code == 0:
            result.exit_code = 2

    if not keep_temp:
        shutil.rmtree(temp_root, ignore_errors=True)
    return result


def _recover_one_table(
    *,
    dbf_path: Path,
    relative: Path,
    source_root: Path,
    output_root: Path,
    dict_dir: Path,
    temp_root: Path,
    overwrite: bool,
    keep_temp: bool,
    outcome: TableOutcome,
) -> None:
    """Odtwarza jedną tabelę: export zaanonimizowanego DBF → recover → reconstruct."""
    rel_posix = relative.as_posix()
    # 1. Eksport zaanonimizowanego DBF do JSONL
    anon_temp = temp_root / "exported" / relative.parent
    anon_temp.mkdir(parents=True, exist_ok=True)
    export_dbf(
        source=dbf_path,
        output=anon_temp,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )
    jsonl_name = relative.with_suffix(".jsonl").name
    anon_jsonl = anon_temp / jsonl_name
    anon_schema = _schema_path_for_jsonl(anon_jsonl)
    if not anon_jsonl.is_file():
        raise FileNotFoundError(f"Eksport nie wygenerował JSONL: {anon_jsonl}")

    # 2. Wczytaj schemat, rekordy i słownik
    schema = load_schema(anon_schema)
    records = _read_jsonl(anon_jsonl)
    data_records = [r for r in records if r.get("type") not in ("summary", "table")]
    outcome.records = len(data_records)

    table_dict = load_dictionary(dbf_path.name, dict_dir)
    if table_dict is None:
        raise FileNotFoundError(
            f"Brak słownika dla tabeli {dbf_path.name} w {dict_dir} "
            f"(szukano {dictionary_filename(dbf_path.name)})"
        )

    # 3. Recover — przywróć oryginalne wartości
    recovered_records = recover_records(schema, records, table_dict)

    # 4. Zapisz zrekonstruowany JSONL + skopiuj schemat
    rec_temp = temp_root / "recovered" / relative.parent
    rec_temp.mkdir(parents=True, exist_ok=True)
    rec_jsonl = rec_temp / jsonl_name
    rec_schema = _schema_path_for_jsonl(rec_jsonl)
    _write_jsonl(rec_jsonl, recovered_records)
    shutil.copyfile(anon_schema, rec_schema)

    # 5. Reconstruct DBF
    out_dbf = output_root / relative
    out_dbf.parent.mkdir(parents=True, exist_ok=True)
    recon = reconstruct_dbf(
        source=rec_temp,
        output=out_dbf.parent,
        input_format="jsonl",
        memo="inline",
        overwrite=True,
    )
    for r in recon.results:
        if r.status == "FAILED":
            outcome.status = "FAILED"
            outcome.errors.extend(r.errors or [f"reconstruct FAILED: {r.source}"])
            return
        if r.warnings:
            outcome.warnings.extend(r.warnings)

    if outcome.errors:
        outcome.status = "FAILED"
    elif outcome.warnings:
        outcome.status = "WARNING"
    else:
        outcome.status = "OK"


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test(
    source_dir: str | Path,
    *,
    memo_mode: str = "mask",
    date_offset_days: int = 0,
    salt: str = "",
    keep_temp: bool = False,
) -> SelfTestReport:
    """Pełny round-trip self-test: source → anonymized → recovered, porównanie.

    Weryfikuje, że po anonimizacji i recovery dane DBF są kanonicznie identyczne
    ze źródłem (wartości pól, liczba rekordów, kolejność, flagi deleted).

    Args:
        source_dir: katalog źródłowy z plikami DBF.
        memo_mode: 'mask' lub 'keep'.
        date_offset_days: offset dni dla D/T.
        salt: sól maskowania.
        keep_temp: zachowaj katalogi pośrednie.

    Returns:
        SelfTestReport z wynikiem per tabela.
    """
    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")

    work_root = source.parent / "var" / f"{source.name}_selftest"
    if work_root.exists():
        shutil.rmtree(work_root, ignore_errors=True)
    work_root.mkdir(parents=True, exist_ok=True)

    anon_dir = work_root / f"{source.name}_anonymized"
    dict_dir = work_root / f"{source.name}_dict"
    rec_dir = work_root / f"{source.name}_recovered"

    # 1. Anonimizacja
    anon_result = anonymize_directory(
        source,
        output_dir=anon_dir,
        dictionary_dir=dict_dir,
        memo_mode=memo_mode,
        date_offset_days=date_offset_days,
        salt=salt,
        overwrite=True,
        keep_temp=True,
    )
    anon_result.raise_for_errors()

    # 2. Recovery
    rec_result = make_dbf_recovery(
        anon_dir,
        dict_dir,
        output_dir=rec_dir,
        overwrite=True,
        keep_temp=True,
    )
    rec_result.raise_for_errors()

    # 3. Porównanie kanoniczne: source DBF vs recovered DBF
    report = SelfTestReport(
        source=source,
        anonymized=anon_dir,
        recovered=rec_dir,
        dictionary_dir=dict_dir,
    )

    source_dbfs = {p.name: p for p in _iter_dbf_files(source)}
    recovered_dbfs = {p.name: p for p in _iter_dbf_files(rec_dir)}

    for table_name, src_dbf in source_dbfs.items():
        rel = _relative_to(src_dbf, source)
        outcome = TableOutcome(table=table_name, relative_path=rel.as_posix())
        rec_dbf = recovered_dbfs.get(table_name)
        if rec_dbf is None:
            outcome.status = "FAILED"
            outcome.errors.append(f"Brak odtworzonego pliku DBF: {table_name}")
            report.tables.append(outcome)
            report.canonical_mismatches += 1
            continue

        # Porównanie kanoniczne przez eksport obu do JSONL i porównanie rekordów
        try:
            match, diff = _compare_dbf_canonical(src_dbf, rec_dbf, work_root, table_name)
            outcome.records = diff["record_count"]
            if match:
                outcome.status = "OK"
                report.canonical_matches += 1
            else:
                outcome.status = "FAILED"
                outcome.errors.append(f"Różnice kanoniczne: {diff['summary']}")
                if diff.get("differences"):
                    outcome.errors.extend(
                        f"rekord {d['record']} pole {d['field']}: "
                        f"expected={d['expected']!r} actual={d['actual']!r}"
                        for d in diff["differences"][:10]
                    )
                report.canonical_mismatches += 1
        except Exception as exc:  # noqa: BLE001
            outcome.status = "FAILED"
            outcome.errors.append(f"Błąd porównania: {exc}")
            report.canonical_mismatches += 1
        report.tables.append(outcome)

    # Tabele w recovered bez odpowiednika w source (nie powinno się zdarzyć)
    for table_name, rec_dbf in recovered_dbfs.items():
        if table_name in source_dbfs:
            continue
        outcome = TableOutcome(table=table_name, relative_path=rec_dbf.name)
        outcome.status = "WARNING"
        outcome.warnings.append("Dodatkowy plik DBF w recovered bez źródła")
        report.tables.append(outcome)

    if report.canonical_mismatches:
        report.exit_code = 1
    elif any(t.status == "WARNING" for t in report.tables):
        report.exit_code = 2
    else:
        report.exit_code = 0

    if not keep_temp:
        shutil.rmtree(work_root, ignore_errors=True)
    return report


def _compare_dbf_canonical(
    src_dbf: Path,
    rec_dbf: Path,
    work_root: Path,
    table_name: str,
) -> tuple[bool, dict[str, Any]]:
    """Porównuje kanonicznie dwa pliki DBF przez eksport do JSONL.

    Zwraca (match, diff). ``diff`` zawiera: record_count, summary, differences.
    """
    cmp_root = work_root / "compare"
    src_out = cmp_root / "src" / table_name
    rec_out = cmp_root / "rec" / table_name
    # Wyczyść jeśli istnieje
    for d in (src_out, rec_out):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    export_dbf(src_dbf, src_out, formats=("jsonl",), memo="inline",
               deleted="include", overwrite=True, validate=False)
    export_dbf(rec_dbf, rec_out, formats=("jsonl",), memo="inline",
               deleted="include", overwrite=True, validate=False)

    src_jsonl = src_out / f"{src_dbf.stem}.jsonl"
    rec_jsonl = rec_out / f"{rec_dbf.stem}.jsonl"
    src_records = [r for r in _read_jsonl(src_jsonl)
                   if r.get("type") not in ("summary", "table")]
    rec_records = [r for r in _read_jsonl(rec_jsonl)
                   if r.get("type") not in ("summary", "table")]

    # Porównanie rekord po rekordzie (klucze pól danych, pomijając __dbfbridge_*)
    data_keys: set[str] = set()
    for r in src_records + rec_records:
        data_keys.update(k for k in r if not k.startswith("__dbfbridge_") and k != "__deleted__")

    differences: list[dict[str, Any]] = []
    max_len = max(len(src_records), len(rec_records))
    for i in range(max_len):
        if i >= len(src_records):
            differences.append({"record": i + 1, "scope": "missing_in_recovered",
                                "expected": "present", "actual": "missing"})
            continue
        if i >= len(rec_records):
            differences.append({"record": i + 1, "scope": "missing_in_source",
                                "expected": "missing", "actual": "present"})
            continue
        src_r = src_records[i]
        rec_r = rec_records[i]
        if src_r.get("__deleted__", False) != rec_r.get("__deleted__", False):
            differences.append({
                "record": i + 1, "field": "__deleted__",
                "expected": src_r.get("__deleted__"),
                "actual": rec_r.get("__deleted__"),
            })
        for key in sorted(data_keys):
            sv = src_r.get(key)
            rv = rec_r.get(key)
            if sv != rv:
                differences.append({
                    "record": i + 1, "field": key,
                    "expected": sv, "actual": rv,
                })
                if len(differences) >= 20:
                    break
        if len(differences) >= 20:
            break

    match = len(differences) == 0 and len(src_records) == len(rec_records)
    diff = {
        "record_count": len(src_records),
        "recovered_count": len(rec_records),
        "summary": (
            f"{len(src_records)} vs {len(rec_records)} rekordów, "
            f"{len(differences)} różnic"
        ),
        "differences": differences,
    }
    return match, diff
