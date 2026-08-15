import argparse
import logging
from pathlib import Path

from dbf_anonymizer.cli import build_parser, main


def test_anonymize_minimal_defaults():
    args = build_parser().parse_args(["anonymize", "D:/DANE_WOM/CWOM-B"])

    assert args.directory == Path("D:/DANE_WOM/CWOM-B")
    assert args.output is None
    assert args.dict_dir is None
    assert args.workers == 0


def test_anonymize_accepts_only_output_and_dictionary_overrides():
    args = build_parser().parse_args([
        "anonymize",
        "D:/DANE_WOM/CWOM-B",
        "--out",
        "D:/Warp_directory/CWOM-B_anonymized",
        "--dict-dir",
        "D:/Secure/CWOM-B_dict",
    ])

    assert args.output == Path("D:/Warp_directory/CWOM-B_anonymized")
    assert args.dict_dir == Path("D:/Secure/CWOM-B_dict")
    assert args.workers == 0


def test_main_logs_final_exit_code(monkeypatch, caplog):
    class Parser:
        @staticmethod
        def parse_args(argv):
            return argparse.Namespace(
                command="anonymize",
                func=lambda args: 2,
            )

    monkeypatch.setattr("dbf_anonymizer.cli._configure_console_utf8", lambda: None)
    monkeypatch.setattr("dbf_anonymizer.cli._configure_logging", lambda args: None)
    monkeypatch.setattr("dbf_anonymizer.cli.build_parser", Parser)
    caplog.set_level(logging.INFO, logger="dbf_anonymizer.cli")

    assert main([]) == 2
    assert any(
        "phase=cli event=done command=anonymize exit_code=2" in record.getMessage()
        for record in caplog.records
    )
