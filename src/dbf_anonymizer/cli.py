"""CLI dla DBF_Anonymizer — argparse z podkomendami.

Użycie:
    dbf-anonymizer anonymize <dir> [--out OUT] [--dict-dir DICT]
        [--memo mask|keep] [--date-offset N] [--salt S]
    dbf-anonymizer recover <anon_dir> <dict_dir> [--out OUT]
    dbf-anonymizer self-test <dir> [--memo mask|keep] [--date-offset N] [--keep-temp]

Punkt wejścia z pyproject.toml: ``dbf-anonymizer`` = ``dbf_anonymizer.cli:main``.
Można też uruchomić: ``python -m dbf_anonymizer``.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .pipeline import (
    AnonymizeResult,
    RecoveryResult,
    SelfTestReport,
    anonymize_directory,
    make_dbf_recovery,
    self_test,
)


def build_parser() -> argparse.ArgumentParser:
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
            "słownik dictionary_<nazwa>.json per tabela (SENSITIWNY — .gitignore)."
        ),
    )
    p_anon.add_argument("directory", type=Path, help="Katalog źródłowy z plikami DBF.")
    p_anon.add_argument("--out", "--output", dest="output", type=Path, default=None,
                        help="Katalog wyjściowy (domyślnie: <directory>_anonymized).")
    p_anon.add_argument("--dict-dir", dest="dict_dir", type=Path, default=None,
                        help="Katalog słowników (domyślnie: <directory>_dict).")
    p_anon.add_argument("--memo", choices=["mask", "keep"], default="mask",
                        help="Pola M/G: 'mask' → 'MEMO' (domyślnie), 'keep' → bez zmian.")
    p_anon.add_argument("--date-offset", dest="date_offset", type=int, default=0,
                        help="Offset dni dla D/T (0 = bez zmian, domyślnie 0).")
    p_anon.add_argument("--salt", default="",
                        help="Sól dla deterministycznego maskowania pól C.")
    p_anon.add_argument("--no-overwrite", dest="overwrite", action="store_false",
                        default=True, help="Nie nadpisuj istniejących plików wyjściowych.")
    p_anon.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                        help="Zachowaj pośrednie JSONL w var/ (debug).")
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
    p_rec.add_argument("anonymized_dir", type=Path,
                       help="Katalog z zaanonimizowanymi plikami DBF.")
    p_rec.add_argument("dictionary_dir", type=Path,
                       help="Katalog ze słownikami (dictionary_*.json).")
    p_rec.add_argument("--out", "--output", dest="output", type=Path, default=None,
                       help="Katalog wyjściowy (domyślnie: <anonymized>_recovered).")
    p_rec.add_argument("--no-overwrite", dest="overwrite", action="store_false",
                       default=True, help="Nie nadpisuj istniejących plików wyjściowych.")
    p_rec.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                       help="Zachowaj pośrednie JSONL (debug).")
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
    p_st.add_argument("directory", type=Path, help="Katalog źródłowy z plikami DBF.")
    p_st.add_argument("--memo", choices=["mask", "keep"], default="mask",
                      help="Pola M/G: 'mask' lub 'keep' (domyślnie mask).")
    p_st.add_argument("--date-offset", dest="date_offset", type=int, default=0,
                      help="Offset dni dla D/T (0 = bez zmian).")
    p_st.add_argument("--salt", default="", help="Sól maskowania pól C.")
    p_st.add_argument("--keep-temp", dest="keep_temp", action="store_true",
                      help="Zachowaj katalogi pośrednie w var/ (debug).")
    p_st.set_defaults(func=_cmd_self_test)

    return parser


def _cmd_anonymize(args: argparse.Namespace) -> int:
    result = anonymize_directory(
        args.directory,
        output_dir=args.output,
        dictionary_dir=args.dict_dir,
        memo_mode=args.memo,
        date_offset_days=args.date_offset,
        salt=args.salt,
        overwrite=args.overwrite,
        keep_temp=args.keep_temp,
    )
    _print_anonymize_result(result)
    return result.exit_code


def _cmd_recover(args: argparse.Namespace) -> int:
    result = make_dbf_recovery(
        args.anonymized_dir,
        args.dictionary_dir,
        output_dir=args.output,
        overwrite=args.overwrite,
        keep_temp=args.keep_temp,
    )
    _print_recovery_result(result)
    return result.exit_code


def _cmd_self_test(args: argparse.Namespace) -> int:
    report = self_test(
        args.directory,
        memo_mode=args.memo,
        date_offset_days=args.date_offset,
        salt=args.salt,
        keep_temp=args.keep_temp,
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
    for t in result.tables:
        flag = {"OK": "✓", "WARNING": "!", "FAILED": "✗"}.get(t.status, "?")
        print(f"  {flag} {t.table} [{t.status}] {t.records} rekordów")
        for err in t.errors:
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
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nPrzerwano.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
