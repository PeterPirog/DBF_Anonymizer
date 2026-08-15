from pathlib import Path

from dbf_anonymizer.cli import build_parser


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
