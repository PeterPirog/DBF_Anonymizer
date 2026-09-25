"""Run REQ-P6-003 against real VFP9 and emit sanitized JSON evidence.

Usage: python tools/run_real_vfp9_acceptance.py --output <evidence.json>

This command is intentionally manual. It resolves only the approved Start Menu
shortcut, requires a clean pushed Git HEAD, runs one opt-in real-runtime test,
and writes an allowlisted evidence record with no local paths or host identity.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
VFP_SHORTCUT = Path(
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    r"\Microsoft Visual FoxPro 9.0.lnk"
)
TEST_IDENTIFIER = (
    "tests/test_p6_vfp_indexed.py::"
    "test_real_vfp9_rebuild_open_count_and_tag_inventory_when_declared"
)
TEST_COMMAND = f"python -m pytest {TEST_IDENTIFIER} -vv -s"
EXPECTED_BRANCH = "p6/vfp-indexed-profile-impl"
EXPECTED_REMOTE_REF = f"origin/{EXPECTED_BRANCH}"
FACT_KEYS = (
    "VFP_VERSION",
    "VFP_TABLE_OPENED",
    "VFP_PUBLISHED_TABLE_OPENED",
    "VFP_RECORD_COUNT",
    "VFP_EXPECTED_TAGS",
    "VFP_ACTUAL_TAGS",
    "VFP_STAGED_TABLE_EXISTED_BEFORE_REBUILD",
    "VFP_STAGED_CDX_EXISTED_BEFORE_REBUILD",
    "SOURCE_DBF_SHA256_BEFORE",
    "SOURCE_DBF_SHA256_AFTER",
    "SOURCE_CDX_SHA256_BEFORE",
    "SOURCE_CDX_SHA256_AFTER",
    "SOURCE_FPT_SHA256_BEFORE",
    "SOURCE_FPT_SHA256_AFTER",
    "OUTPUT_DBF_SHA256",
    "OUTPUT_CDX_SHA256",
    "SOURCE_IMMUTABLE",
    "FRESH_CDX",
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ABSOLUTE_WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]")
_PRIVATE_TOKENS = (
    "project_dbfanonymizer",
    "c:\\users",
    "users\\",
    "peter",
    "appdata",
    "desktop",
    "documents",
    "downloads",
    "dictionary.sqlite3",
    "private-memo-canary",
    "private00001",
    "key0001",
    "synth-a",
)


def _fail(message: str) -> None:
    raise SystemExit(f"real VFP9 acceptance FAILED: {message}")


def _run_git(*args: str) -> str:
    completed = subprocess.run(
        ("git", *args),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        _fail("Git provenance check failed")
    return completed.stdout.strip()


def _verified_git_state() -> tuple[str, str]:
    if _run_git("status", "--porcelain", "--untracked-files=no"):
        _fail("tracked worktree changes are present")
    branch = _run_git("branch", "--show-current")
    if branch != EXPECTED_BRANCH:
        _fail("the acceptance command is not running on the PR #43 branch")
    head = _run_git("rev-parse", "HEAD")
    pushed_head = _run_git("rev-parse", EXPECTED_REMOTE_REF)
    if head != pushed_head:
        _fail("HEAD is not the exact pushed PR branch commit")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        _fail("Git returned a malformed commit identifier")
    return branch, head


def _resolve_vfp9() -> Path:
    if platform.system() != "Windows":
        _fail("the trusted runner must be Windows")
    if not VFP_SHORTCUT.is_file():
        _fail("the approved Visual FoxPro shortcut is unavailable")
    powershell = (
        "$shortcut = (New-Object -ComObject WScript.Shell)."
        "CreateShortcut($args[0]); "
        "[Console]::Out.Write($shortcut.TargetPath)"
    )
    completed = subprocess.run(
        (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            powershell,
            str(VFP_SHORTCUT),
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        _fail("the approved shortcut could not be resolved")
    executable = Path(completed.stdout.strip())
    if executable.name.lower() != "vfp9.exe" or not executable.is_file():
        _fail("the approved shortcut target is not an available vfp9.exe")
    return executable


def _parse_facts(output: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in output.splitlines():
        for key in FACT_KEYS:
            prefix = f"{key}="
            if prefix in line:
                facts[key] = line.split(prefix, 1)[1].strip()
                break
    missing = sorted(set(FACT_KEYS) - facts.keys())
    if missing:
        _fail("the real-runtime test did not emit complete evidence facts")
    return facts


def _require_bool(facts: dict[str, str], key: str, expected: bool) -> None:
    actual = facts[key]
    expected_text = str(expected)
    if actual != expected_text:
        _fail(f"evidence fact {key} was {actual!r}, expected {expected_text!r}")


def _require_sha256(facts: dict[str, str], key: str) -> str:
    value = facts[key]
    if _SHA256.fullmatch(value) is None:
        _fail(f"evidence fact {key} is not SHA-256")
    return value


def _build_evidence(
    branch: str, commit: str, facts: dict[str, str]
) -> dict[str, object]:
    _require_bool(facts, "VFP_TABLE_OPENED", True)
    _require_bool(facts, "VFP_PUBLISHED_TABLE_OPENED", True)
    _require_bool(facts, "VFP_STAGED_TABLE_EXISTED_BEFORE_REBUILD", True)
    _require_bool(facts, "VFP_STAGED_CDX_EXISTED_BEFORE_REBUILD", False)
    _require_bool(facts, "SOURCE_IMMUTABLE", True)
    _require_bool(facts, "FRESH_CDX", True)
    if facts["VFP_VERSION"] != "Visual FoxPro 09.00.0000.5815 for Windows":
        _fail("the real VFP9 runtime version is not the accepted version")

    source_hashes: dict[str, dict[str, str]] = {}
    for artifact in ("DBF", "CDX", "FPT"):
        before = _require_sha256(facts, f"SOURCE_{artifact}_SHA256_BEFORE")
        after = _require_sha256(facts, f"SOURCE_{artifact}_SHA256_AFTER")
        if before != after:
            _fail(f"source {artifact} changed during real-runtime acceptance")
        source_hashes[artifact.lower()] = {"before": before, "after": after}

    output_dbf = _require_sha256(facts, "OUTPUT_DBF_SHA256")
    output_cdx = _require_sha256(facts, "OUTPUT_CDX_SHA256")
    if output_cdx == source_hashes["cdx"]["before"]:
        _fail("rebuilt output CDX is identical to the source CDX")

    expected_tags = facts["VFP_EXPECTED_TAGS"].split(",")
    actual_tags = facts["VFP_ACTUAL_TAGS"].split(",")
    if expected_tags != ["SYNTHCODE", "SYNTHNOTE"] or actual_tags != expected_tags:
        _fail("real VFP9 tag inventory does not match the synthetic fixture")
    if facts["VFP_RECORD_COUNT"] != "4":
        _fail("real VFP9 record count does not match the synthetic fixture")

    return {
        "evidence_schema_version": "1.0",
        "requirement": "REQ-P6-003",
        "synthetic": True,
        "execution": {
            "completed_at_utc": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "dbf_anonymizer_git_branch": branch,
            "dbf_anonymizer_git_commit": commit,
            "dbfbridge_version": importlib.metadata.version("dbfbridge"),
            "platform": "Windows",
            "python_version": platform.python_version(),
            "runner": "explicitly-invoked trusted local Windows runner",
            "test_command": TEST_COMMAND,
            "test_identifier": TEST_IDENTIFIER,
            "result": "PASS",
            "pytest_passed": 1,
            "pytest_skipped": 0,
        },
        "vfp": {
            "launched": True,
            "version": facts["VFP_VERSION"],
        },
        "verification": {
            "actual_tag_inventory": actual_tags,
            "authoritative_source_tags_read": True,
            "expected_tag_inventory": expected_tags,
            "fresh_cdx": True,
            "fresh_staged_dbf": True,
            "output_cdx_differs_from_source": True,
            "published_table_opened": True,
            "rebuilt_staged_cdx": True,
            "record_count": 4,
            "source_immutable": True,
            "staged_table_opened": True,
        },
        "sha256": {
            "source": source_hashes,
            "output": {"dbf": output_dbf, "cdx": output_cdx},
        },
        "privacy": {
            "allowlisted_fields_only": True,
            "public_surfaces_sanitized": True,
            "path_leak_scan": {
                "clean": True,
                "method": "drive-path regex and private-token scan over JSON text",
            },
        },
    }


def _sanitized_json(evidence: dict[str, object]) -> str:
    rendered = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    lowered = rendered.lower()
    if _ABSOLUTE_WINDOWS_PATH.search(rendered) is not None:
        _fail("absolute path leaked into the evidence record")
    if any(token in lowered for token in _PRIVATE_TOKENS):
        _fail("a private token leaked into the evidence record")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="JSON evidence destination (system TEMP is recommended)",
    )
    args = parser.parse_args()
    if args.output.exists():
        _fail("the evidence destination already exists")

    branch, commit = _verified_git_state()
    executable = _resolve_vfp9()
    env = dict(os.environ)
    env.update(
        {
            "DBF_ANONYMIZER_REAL_VFP9_AVAILABLE": "1",
            "DBF_ANONYMIZER_REAL_VFP9_BACKEND_FACTORY": (
                "tests.support.real_vfp9_backend:create_backend"
            ),
            "DBF_ANONYMIZER_REAL_VFP9_EXECUTABLE": str(executable),
        }
    )
    completed = subprocess.run(
        (sys.executable, "-m", "pytest", TEST_IDENTIFIER, "-vv", "-s"),
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=300,
    )
    combined_output = completed.stdout + "\n" + completed.stderr
    passed_node = TEST_IDENTIFIER in combined_output
    passed_status = re.search(
        r"(?m)^PASSED(?:\s+\[\s*100%\])?\s*$", combined_output
    )
    passed_summary = re.search(r"\b1 passed\b", combined_output)
    if (
        completed.returncode != 0
        or not passed_node
        or passed_status is None
        or passed_summary is None
    ):
        _fail("the real VFP9 pytest node did not PASS")
    if re.search(r"\bSKIPPED\b", combined_output) is not None:
        _fail("the real VFP9 pytest node was skipped")

    evidence = _build_evidence(branch, commit, _parse_facts(combined_output))
    rendered = _sanitized_json(evidence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="ascii")

    print("real VFP9 acceptance PASSED (1 passed, 0 skipped)")
    print(f"tested commit: {commit}")
    print("machine-readable evidence written to the requested destination")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
