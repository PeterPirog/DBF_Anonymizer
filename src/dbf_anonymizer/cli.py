"""CLI dla DBF_Anonymizer — argparse z podkomendami.

Użycie:
    dbf-anonymizer anonymize [<dir>] [--out OUT] [--dict-dir DICT]
    dbf-anonymizer recover <anon_dir> <dict_dir> [--out OUT] [--workers N]
    dbf-anonymizer self-test <dir> [--memo mask|keep] [--date-offset N]
        [--workers N] [--keep-temp]

Punkt wejścia z pyproject.toml: ``dbf-anonymizer`` = ``dbf_anonymizer.cli:main``.
Można też uruchomić: ``python -m dbf_anonymizer``. Brakujące ścieżki mogą być
wczytane z lokalnego pliku ``.env``.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .envconfig import (
    env_bool,
    env_int,
    env_list,
    env_path,
    env_text,
    load_env_file,
)
from .pipeline import (
    AnonymizeResult,
    RecoveryResult,
    SelfTestReport,
    anonymize_directory,
    make_dbf_recovery,
    self_test,
)


def build_parser() -> argparse.ArgumentParser:
    workers_default = env_int("DBF_ANON_WORKERS", 0, minimum=0)
    batch_default = env_int("DBF_ANON_BATCH_SIZE", 5000, minimum=1)
    vfp_progid_default = env_text(
        "DBF_ANON_VFP_PROGID", "VisualFoxPro.Application"
    )
    parser = argparse.ArgumentParser(
        prog="dbf-anonymizer",
        description=(
            "Framework do anonimizacji plików DBF (Visual FoxPro) z odwracalnym "
            "słownikiem. Anonimizuje katalog DBF → <dir>_anonymized + słowniki, "
            "a następnie pozwala odtworzyć oryginał: <anon>_recovered."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # anonymize
    p_anon = sub.add_parser(
        "anonymize",
        help="Anonimizuj katalog DBF → <dir>_anonymized + słowniki.",
        description=(
            "Anonimizuje wszystkie pliki DBF w katalogu źródłowym. Tworzy katalog "
            "wyjściowy z identyczną strukturą plików DBF (zanonimizowane dane) oraz "
            "jeden globalny dictionary.sqlite3 dla całej bazy "
            "(SENSITIWNY — .gitignore)."
        ),
    )
    p_anon.add_argument(
        "directory", nargs="?", type=Path, default=env_path("DBF_ANON_SOURCE"),
        help="Katalog źródłowy z DBF (lub DBF_ANON_SOURCE z .env).",
    )
    p_anon.add_argument("--out", "--output", dest="output", type=Path,
                        default=env_path("DBF_ANON_OUTPUT"),
                        help="Katalog wyjściowy (domyślnie: <directory>_anonymized).")
    p_anon.add_argument("--dict-dir", dest="dict_dir", type=Path,
                        default=env_path("DBF_ANON_DICTIONARY"),
                        help=(
                            "Katalog słownika (domyślnie: <directory>_dict obok "
                            "katalogu wyjściowego)."
                        ))
    p_anon.add_argument("--memo", choices=["mask", "keep"], default="mask",
                        help="Pola M/G: 'mask' → 'MEMO' (domyślnie), 'keep' → bez zmian.")
    p_anon.add_argument("--date-offset", dest="date_offset", type=int, default=0,
                        help="Offset dni dla D/T (0 = bez zmian, domyślnie 0).")
    p_anon.add_argument("--salt", default=env_text("DBF_ANON_SALT"),
                        help="Sól dla deterministycznego maskowania pól C.")
    p_anon.add_argument("--no-overwrite", dest="overwrite", action="store_false",
                        default=True, help="Nie nadpisuj istniejących plików wyjściowych.")
    p_anon.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                        help="Zachowaj pośrednie JSONL w var/ (debug).")
    p_anon.add_argument("--workers", type=_non_negative_int, default=workers_default,
                        help="Liczba procesów (0 = automatycznie, 1 = sekwencyjnie).")
    p_anon.add_argument("--batch-size", type=_positive_int, default=batch_default,
                        help="Rekordy JSONL na partię (domyślnie 5000).")
    p_anon.add_argument(
        "--fresh-dictionary",
        action="store_true",
        help="Nie zachowuj istniejących mapowań; zbuduj słownik od zera.",
    )
    p_anon.add_argument(
        "--vfp-progid",
        default=vfp_progid_default,
        help="ProgID serwera COM VFP używanego do obowiązkowego REINDEX CDX.",
    )
    _add_vfp_and_exclusion_arguments(p_anon)
    _add_logging_arguments(p_anon)
    p_anon.set_defaults(func=_cmd_anonymize)

    # recover
    p_rec = sub.add_parser(
        "recover",
        help="Odtwórz oryginał z katalogu zaanonimizowanego + słowników.",
        description=(
            "Odtwarza pierwotne dane DBF z katalogu zaanonimizowanego i słowników. "
            "Tworzy katalog <anonymized>_recovered z pierwotnymi wartościami pól."
        ),
    )
    p_rec.add_argument("anonymized_dir", nargs="?", type=Path,
                       default=env_path("DBF_ANON_OUTPUT"),
                       help="Katalog z zaanonimizowanymi plikami DBF.")
    p_rec.add_argument("dictionary_dir", nargs="?", type=Path,
                       default=env_path("DBF_ANON_DICTIONARY"),
                       help="Katalog z dictionary.sqlite3 (lub starszymi JSON v1/v2).")
    p_rec.add_argument("--out", "--output", dest="output", type=Path,
                       default=env_path("DBF_ANON_RECOVERED"),
                       help="Katalog wyjściowy (domyślnie: <anonymized>_recovered).")
    p_rec.add_argument("--no-overwrite", dest="overwrite", action="store_false",
                       default=True, help="Nie nadpisuj istniejących plików wyjściowych.")
    p_rec.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                       help="Zachowaj pośrednie JSONL (debug).")
    p_rec.add_argument("--workers", type=_non_negative_int, default=workers_default,
                       help="Liczba procesów (0 = automatycznie, 1 = sekwencyjnie).")
    p_rec.add_argument("--batch-size", type=_positive_int, default=batch_default,
                       help="Rekordy JSONL na partię (domyślnie 5000).")
    p_rec.add_argument(
        "--vfp-progid",
        default=vfp_progid_default,
        help="ProgID serwera COM VFP używanego do obowiązkowego REINDEX CDX.",
    )
    _add_vfp_and_exclusion_arguments(p_rec)
    _add_logging_arguments(p_rec)
    p_rec.set_defaults(func=_cmd_recover)

    # self-test
    p_st = sub.add_parser(
        "self-test",
        help="Pełny round-trip: source → anonymized → recovered, porównanie.",
        description=(
            "Wykonuje pełny round-trip (anonimizacja + recovery) na katalogu DBF "
            "i weryfikuje, że zrekonstruowany DBF jest kanonicznie identyczny ze "
            "źródłowym (wartości pól, liczba rekordów, kolejność, flagi deleted)."
        ),
    )
    p_st.add_argument(
        "directory", nargs="?", type=Path, default=env_path("DBF_ANON_SOURCE"),
        help="Katalog źródłowy z DBF (lub DBF_ANON_SOURCE z .env).",
    )
    p_st.add_argument("--memo", choices=["mask", "keep"], default="mask",
                      help="Pola M/G: 'mask' lub 'keep' (domyślnie mask).")
    p_st.add_argument("--date-offset", dest="date_offset", type=int, default=0,
                      help="Offset dni dla D/T (0 = bez zmian).")
    p_st.add_argument("--salt", default=env_text("DBF_ANON_SALT"),
                      help="Sól maskowania pól C.")
    p_st.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                      help="Zachowaj katalogi pośrednie w var/ (debug).")
    p_st.add_argument("--workers", type=_non_negative_int, default=workers_default,
                      help="Liczba procesów (0 = automatycznie, 1 = sekwencyjnie).")
    p_st.add_argument("--batch-size", type=_positive_int, default=batch_default,
                      help="Rekordy JSONL na partię (domyślnie 5000).")
    p_st.add_argument(
        "--vfp-progid",
        default=vfp_progid_default,
        help="ProgID serwera COM VFP do REINDEX i testu otwarcia/CDX.",
    )
    _add_vfp_and_exclusion_arguments(p_st)
    _add_logging_arguments(p_st)
    p_st.set_defaults(func=_cmd_self_test)

    return parser


def _cmd_anonymize(args: argparse.Namespace) -> int:
    directory = _require_path(args.directory, "directory", "DBF_ANON_SOURCE")
    result = anonymize_directory(
        directory,
        output_dir=args.output,
        dictionary_dir=args.dict_dir,
        memo_mode=args.memo,
        date_offset_days=args.date_offset,
        salt=args.salt,
        overwrite=args.overwrite,
        keep_temp=args.keep_temp,
        workers=args.workers,
        batch_size=args.batch_size,
        reuse_dictionary=not args.fresh_dictionary,
        vfp_progid=args.vfp_progid,
        vfp_executable=args.vfp_exe,
        exclude_patterns=args.exclude,
        include_system_files=args.include_system_files,
    )
    _print_anonymize_result(result)
    return result.exit_code


def _cmd_recover(args: argparse.Namespace) -> int:
    anonymized_dir = _require_path(
        args.anonymized_dir, "anonymized_dir", "DBF_ANON_OUTPUT"
    )
    dictionary_dir = _require_path(
        args.dictionary_dir, "dictionary_dir", "DBF_ANON_DICTIONARY"
    )
    result = make_dbf_recovery(
        anonymized_dir,
        dictionary_dir,
        output_dir=args.output,
        overwrite=args.overwrite,
        keep_temp=args.keep_temp,
        workers=args.workers,
        batch_size=args.batch_size,
        vfp_progid=args.vfp_progid,
        vfp_executable=args.vfp_exe,
        exclude_patterns=args.exclude,
        include_system_files=args.include_system_files,
    )
    _print_recovery_result(result)
    return result.exit_code


def _cmd_self_test(args: argparse.Namespace) -> int:
    directory = _require_path(args.directory, "directory", "DBF_ANON_SOURCE")
    report = self_test(
        directory,
        memo_mode=args.memo,
        date_offset_days=args.date_offset,
        salt=args.salt,
        keep_temp=args.keep_temp,
        workers=args.workers,
        batch_size=args.batch_size,
        vfp_progid=args.vfp_progid,
        vfp_executable=args.vfp_exe,
        exclude_patterns=args.exclude,
        include_system_files=args.include_system_files,
    )
    _print_self_test_report(report)
    return report.exit_code


def _print_anonymize_result(result: AnonymizeResult) -> None:
    print(f"Źródło:    {result.source}")
    print(f"Wyjście:   {result.output}")
    print(f"Słowniki:  {result.dictionary_dir}")
    print()
    ok = sum(1 for t in result.tables if t.status == "OK")
    warn = sum(1 for t in result.tables if t.status == "WARNING")
    fail = sum(1 for t in result.tables if t.status == "FAILED")
    print(f"Podsumowanie: OK={ok}  Ostrzeżenia={warn}  Błędy={fail}")
    if result.global_error:
        print(
            f"BŁĄD GLOBALNY [{result.global_error_code or 'UNKNOWN'}]: "
            f"{result.global_error}"
        )
        print(f"Zablokowane tabele: {fail}")
    for t in result.tables:
        flag = {"OK": "✓", "WARNING": "!", "FAILED": "✗"}.get(t.status, "?")
        print(f"  {flag} {t.table} [{t.status}] {t.records} rekordów")
        for err in t.errors:
            if result.global_error and result.global_error in err:
                continue
            print(f"      BŁĄD: {err}")
        for w in t.warnings:
            print(f"      ostrzeż.: {w}")
    print()
    print("UWAGA: Słowniki w .gitignore — zawierają mapowanie oryginał↔anonim.")
    print("       Nie wysyłaj ich na GitHub/serwer!")


def _print_recovery_result(result: RecoveryResult) -> None:
    print(f"Źródło (zaanonimizowane): {result.source}")
    print(f"Słowniki:                 {result.dictionary_dir}")
    print(f"Wyjście (odtworzone):     {result.output}")
    print()
    ok = sum(1 for t in result.tables if t.status == "OK")
    warn = sum(1 for t in result.tables if t.status == "WARNING")
    fail = sum(1 for t in result.tables if t.status == "FAILED")
    print(f"Podsumowanie: OK={ok}  Ostrzeżenia={warn}  Błędy={fail}")
    for t in result.tables:
        flag = {"OK": "✓", "WARNING": "!", "FAILED": "✗"}.get(t.status, "?")
        print(f"  {flag} {t.table} [{t.status}] {t.records} rekordów")
        for err in t.errors:
            print(f"      BŁĄD: {err}")
        for w in t.warnings:
            print(f"      ostrzeż.: {w}")


def _print_self_test_report(report: SelfTestReport) -> None:
    print("=" * 60)
    print("SELF-TEST: round-trip source → anonymized → recovered")
    print("=" * 60)
    print(f"Źródło:           {report.source}")
    print(f"Zaanonimizowane:  {report.anonymized}")
    print(f"Słowniki:         {report.dictionary_dir}")
    print(f"Odtworzone:       {report.recovered}")
    print()
    print(f"Kanoniczne dopasowania:    {report.canonical_matches}")
    print(f"Kanoniczne niezgodności:   {report.canonical_mismatches}")
    print()
    for t in report.tables:
        flag = {"OK": "✓", "WARNING": "!", "FAILED": "✗"}.get(t.status, "?")
        print(f"  {flag} {t.table} [{t.status}] {t.records} rekordów")
        for err in t.errors:
            print(f"      BŁĄD: {err}")
        for w in t.warnings:
            print(f"      ostrzeż.: {w}")
    print()
    if report.successful:
        print("WYNIK: PASS — wszystkie tabele round-trip kanonicznie identyczne.")
    else:
        print("WYNIK: FAIL — wystąpiły niezgodności (patrz wyżej).")


def main(argv: list[str] | None = None) -> int:
    _configure_console_utf8()
    try:
        loaded_env = load_env_file()
        parser = build_parser()
    except (OSError, ValueError) as exc:
        print(f"Błąd konfiguracji .env: {exc}", file=sys.stderr)
        return 1
    args = parser.parse_args(argv)
    _configure_logging(args)
    cli_logger = logging.getLogger(__name__)
    cli_logger.info(
        "phase=cli event=start command=%s version=%s python=%s",
        args.command,
        __version__,
        sys.executable,
    )
    if loaded_env is not None:
        cli_logger.info("phase=cli event=env_loaded path=%s", loaded_env)
    try:
        exit_code = args.func(args)
    except FileNotFoundError as exc:
        cli_logger.error(
            "phase=cli event=failed error_code=FILE_NOT_FOUND error=%s",
            exc,
        )
        print(f"Błąd: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        cli_logger.warning("phase=cli event=interrupted")
        print("\nPrzerwano.", file=sys.stderr)
        return 130
    except Exception as exc:
        cli_logger.exception(
            "phase=cli event=failed error_code=%s error=%s",
            type(exc).__name__,
            exc,
        )
        print(f"Błąd krytyczny: {exc}", file=sys.stderr)
        return 1
    cli_logger.info(
        "phase=cli event=done command=%s exit_code=%d",
        args.command,
        exit_code,
    )
    return exit_code


def _add_logging_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=env_text("DBF_ANON_LOG_LEVEL", "INFO").upper(),
        help="Szczegółowość logów diagnostycznych (domyślnie INFO).",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=env_path("DBF_ANON_LOG_FILE"),
        help="Opcjonalny plik UTF-8 z logiem nadającym się do analizy błędów.",
    )


def _add_vfp_and_exclusion_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--vfp-exe",
        type=Path,
        default=env_path("DBF_ANON_VFP_EXE"),
        help=(
            "Opcjonalna ścieżka vfp9.exe do wczesnej walidacji instalacji; "
            "automatyzacja nadal używa COM."
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=env_list("DBF_ANON_EXCLUDE"),
        metavar="GLOB",
        help=(
            "Świadomie pomiń DBF wg ścieżki względnej; można powtórzyć. "
            "W .env wzorce rozdziela się średnikami."
        ),
    )
    parser.add_argument(
        "--include-system-files",
        action="store_true",
        default=env_bool("DBF_ANON_INCLUDE_SYSTEM_FILES", False),
        help="Włącz domyślnie pomijany zasób środowiska FOXUSER.DBF.",
    )


def _require_path(value: Path | None, argument: str, environment: str) -> Path:
    if value is None:
        raise ValueError(
            f"[REQUIRED_PATH_MISSING] Podaj {argument} albo ustaw {environment} w .env"
        )
    return value


def _configure_logging(args: argparse.Namespace) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    log_file = getattr(args, "log_file", None)
    if log_file is not None:
        log_path = Path(log_file).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, getattr(args, "log_level", "INFO")),
        format=(
            "%(asctime)s level=%(levelname)s pid=%(process)d "
            "logger=%(name)s %(message)s"
        ),
        handlers=handlers,
        force=True,
    )


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("wartość musi być >= 0")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("wartość musi być > 0")
    return parsed


def _configure_console_utf8() -> None:
    """Ujednolica polskie znaki w PowerShell/PyCharm i plikach logu."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="backslashreplace")
            except (OSError, ValueError):
                pass


if __name__ == "__main__":
    sys.exit(main())
