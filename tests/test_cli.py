import argparse
import logging
from pathlib import Path

from dbf_anonymizer.cli import build_parser, main
from dbf_anonymizer.envconfig import load_env_file


def test_anonymize_minimal_defaults():
    args = build_parser().parse_args(["anonymize", "C:/Data/LegacyDB"])

    assert args.directory == Path("C:/Data/LegacyDB")
    assert args.output is None
    assert args.dict_dir is None
    assert args.workers == 0


def test_anonymize_accepts_only_output_and_dictionary_overrides():
    args = build_parser().parse_args([
        "anonymize",
        "C:/Data/LegacyDB",
        "--out",
        "C:/DBF_Work/LegacyDB_anonymized",
        "--dict-dir",
        "D:/Secure/LegacyDB_dict",
    ])

    assert args.output == Path("C:/DBF_Work/LegacyDB_anonymized")
    assert args.dict_dir == Path("D:/Secure/LegacyDB_dict")
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


def test_env_file_allows_pathless_short_command(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                r"DBF_ANON_SOURCE=C:\Data\LegacyDB",
                r"DBF_ANON_OUTPUT=C:\DBF_Work\LegacyDB_anonymized",
                r"DBF_ANON_DICTIONARY=C:\DBF_Work\LegacyDB_dict",
                "DBF_ANON_WORKERS=0",
                "DBF_ANON_EXCLUDE=DATA/memo_table.dbf;archiwum/*.dbf",
            ]
        ),
        encoding="utf-8",
    )
    for name in (
        "DBF_ANON_SOURCE",
        "DBF_ANON_OUTPUT",
        "DBF_ANON_DICTIONARY",
        "DBF_ANON_WORKERS",
        "DBF_ANON_EXCLUDE",
    ):
        monkeypatch.delenv(name, raising=False)

    load_env_file(env_file)
    args = build_parser().parse_args(["anonymize"])

    assert args.directory == Path(r"C:\Data\LegacyDB")
    assert args.output == Path(r"C:\DBF_Work\LegacyDB_anonymized")
    assert args.dict_dir == Path(r"C:\DBF_Work\LegacyDB_dict")
    assert args.exclude == ["DATA/memo_table.dbf", "archiwum/*.dbf"]


def test_environment_overrides_env_file(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("DBF_ANON_SOURCE=D:\\from-file\n", encoding="utf-8")
    monkeypatch.setenv("DBF_ANON_SOURCE", r"D:\from-powershell")

    load_env_file(env_file)

    assert build_parser().parse_args(["anonymize"]).directory == Path(
        r"D:\from-powershell"
    )
