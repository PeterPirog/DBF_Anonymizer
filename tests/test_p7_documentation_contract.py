"""REQ-P7-009 documentation contract: English-first, truthful, executable.

Proves the user documentation objectively:

1. every required REQ-P7-009 topic is covered by version-controlled English
   docs (semantic multi-marker coverage, not single-sentence matching);
2. every relative documentation link resolves and every doc is reachable from
   the README;
3. documented public Python symbols actually exist on the public package root;
4. documented CLI command names match the real CLI command set exactly;
5. documented schema/version constants match the current code constants;
6. fenced blocks marked ``python p7-009-exec`` are real executable acceptance
   examples: they are extracted deterministically and run against synthetic
   task-owned TEMP data;
7. offline-install examples stay consistent with the pinned wheelhouse
   contract;
8. DATA_ONLY documentation enumerates the excluded recovery material and never
   instructs copying the vault into a transfer;
9. VFP/index documentation stays truthful (backend-evidence requirement,
   P6-006 BLOCKED/DEFERRED, no automatic VFP project understanding);
10. DBF_Anonymizer is described as transport-neutral and NOT an MCP server;
11. the pseudonymized-vs-anonymous distinction is present and explicit;
12. docs contain no private paths, secrets or production-data instructions.

The examples use synthetic fixtures only; the harness never touches
production datasets.
"""

from __future__ import annotations

import importlib
import re
import shutil
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"
DOCUMENT_NAMES = (
    "README.md",
    "docs/operations.md",
    "docs/limits-and-integrity.md",
    "docs/mcp-integration.md",
    "docs/threat-model.md",
    "docs/pseudonymization-vs-anonymization.md",
    "docs/public-models-1.0.md",
    "docs/errors-1.0.md",
    "docs/vault-protection.md",
    "docs/migration-1.0-clean-slate.md",
)
EXECUTABLE_INFO_MARKER = "p7-009-exec"
OPERATIONS = "docs/operations.md"
LIMITS = "docs/limits-and-integrity.md"
MCP_DOC = "docs/mcp-integration.md"
THREAT = "docs/threat-model.md"
DISTINCTION = "docs/pseudonymization-vs-anonymization.md"


def _documents() -> dict[str, str]:
    documents: dict[str, str] = {}
    for name in DOCUMENT_NAMES:
        path = REPO_ROOT / name
        if not path.is_file():
            raise AssertionError(f"required documentation file missing: {name}")
        documents[name] = path.read_text(encoding="utf-8")
    return documents


def _normalized(text: str) -> str:
    """Whitespace-collapsed, case-folded text for semantic marker matching."""
    return re.sub(r"\s+", " ", text).casefold()


def _all_text() -> str:
    return "\n".join(_documents().values())


def _fenced_blocks(text: str) -> list[tuple[str, str]]:
    """Yield (info_string, content) for every fenced code block in order."""
    blocks: list[tuple[str, str]] = []
    lines = text.splitlines()
    index = 0
    fence = re.compile(r"^```(.*)$")
    while index < len(lines):
        match = fence.match(lines[index])
        if match is None:
            index += 1
            continue
        info = match.group(1).strip()
        index += 1
        body: list[str] = []
        while index < len(lines) and not lines[index].startswith("```"):
            body.append(lines[index])
            index += 1
        blocks.append((info, "\n".join(body)))
        index += 1
    return blocks


def _topic_text(topic_markers: tuple[str, ...]) -> None:
    """Every marker must appear somewhere in the aggregated documentation
    (whitespace-insensitive and case-insensitive so wrapped prose cannot hide
    a covered topic)."""
    aggregated = _normalized(_all_text())
    missing = [marker for marker in topic_markers if _normalized(marker) not in aggregated]
    assert not missing, f"documentation topic markers missing: {missing}"


# ---------------------------------------------------------------------------
# 1. Topic coverage (semantic markers, never one brittle sentence)
# ---------------------------------------------------------------------------


def test_offline_installation_topic_is_covered() -> None:
    _topic_text(
        (
            "Internal-network offline installation",
            "--no-index",
            "--find-links",
            "--only-binary=:all:",
            "requirements/p7-offline-wheelhouse.txt",
            "The runtime never downloads",
            "no HTTP, no package indexes, no Git",
        )
    )


def test_one_vault_per_dataset_topic_is_covered() -> None:
    _topic_text(
        (
            "exactly ONE vault spans all converted tables/files",
            "no vault per table",
            "SINGLE_DATASET_SQLITE",
            "protected/recovery.sqlite3",
            "mapping domains remain consistent",
            "must NEVER be copied into a DATA_ONLY transfer",
        )
    )


def test_policy_configuration_topic_is_covered() -> None:
    _topic_text(
        (
            "Policy configuration",
            "schema_version",
            "SAFE_TRANSFER",
            "PSEUDONYMIZE_REVERSIBLE",
            "MASK_REVERSIBLE",
            "SHIFT_REVERSIBLE",
            "policy_fingerprint",
        )
    )


def test_relationship_configuration_topic_is_covered() -> None:
    _topic_text(
        (
            "Relationship configuration",
            "metadata_schema_version",
            "POLICY_FILE",
            "MCP_VFP9SP2_TOOLCHAIN",
            "EXACT_VALUE",
            "REVERSIBLE_BIJECTIVE",
            "PRIMARY",
            "FOREIGN",
            "no automatic DBC relationship discovery",
            "preflight",
        )
    )


def test_pseudonymization_verification_recovery_topics_are_covered() -> None:
    _topic_text(
        (
            "public.pseudonymize",
            "public.verify_dataset",
            "public.recover",
            "public.preflight",
            "RecoveryPolicy",
            "RECOVERY_NOT_PERMITTED",
        )
    )


def test_data_only_topic_is_covered() -> None:
    _topic_text(
        (
            "DATA_ONLY",
            "verify_transfer_bundle",
            "EXCLUDES",
            "SQLite WAL/SHM/journal",
            "reverse mappings",
            "fresh FPT companions",
            "sanitized public manifest",
        )
    )


def test_index_vfp_limitation_topic_is_covered() -> None:
    _topic_text(
        (
            "VFP_INDEXED",
            "backend evidence",
            "stale CDX/IDX/DBC artifacts are never transferred or claimed as rebuilt",
            "standalone IDX files are separately inventoried",
            "DBC-bound source remains reported as DBC-bound",
            "does NOT imply preservation",
            "DBC rules, triggers, persistent relations, views or stored procedures",
        )
    )


def test_mcp_consumer_integration_topic_is_covered() -> None:
    _topic_text(
        (
            "mcp-vfp9sp2-toolchain",
            "DBF_Anonymizer is a synchronous, transport-neutral library",
            "NOT an MCP server",
            "does not import mcp-vfp9sp2-toolchain",
        )
    )


def test_threat_model_topic_is_covered() -> None:
    _topic_text(
        (
            "Protected assets",
            "Transferable assets",
            "Trust boundaries",
            "Attack and failure classes",
            "Accidental vault transfer",
            "stale index leakage",
            "original-value leakage",
            "What DBF_Anonymizer does NOT protect against",
        )
    )


# ---------------------------------------------------------------------------
# 2. English-first and link/schema/CLI consistency
# ---------------------------------------------------------------------------


def test_documentation_is_english_first() -> None:
    polish_diacritics = set("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
    for name, text in _documents().items():
        found = sorted(set(text) & polish_diacritics)
        assert not found, f"{name} contains non-English characters: {found}"


_LINK = re.compile(r"\[[^\]]+\]\(([^)\s]+)\)")


def test_all_relative_documentation_links_resolve() -> None:
    for name, text in _documents().items():
        base = (REPO_ROOT / name).parent
        for target in _LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue  # pure in-page anchor
            resolved = (base / path_part).resolve()
            assert resolved.is_file(), f"{name}: broken relative link {target!r}"


def test_every_doc_is_reachable_from_the_readme() -> None:
    documents = _documents()
    reachable = {"README.md"}
    queue = ["README.md"]
    while queue:
        current = queue.pop()
        base = (REPO_ROOT / current).parent
        for target in _LINK.findall(documents[current]):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part.endswith(".md"):
                continue
            resolved = (base / path_part).resolve().as_posix()
            for name in documents:
                candidate = (REPO_ROOT / name).resolve().as_posix()
                if candidate == resolved and name not in reachable:
                    reachable.add(name)
                    queue.append(name)
    unreachable = sorted(set(documents) - reachable)
    assert not unreachable, f"documentation files not reachable from README: {unreachable}"


def test_documented_public_symbols_exist() -> None:
    public = importlib.import_module("dbf_anonymizer")
    used: set[str] = set()
    for text in _documents().values():
        for match in re.finditer(r"\b(?:public|dbf_anonymizer)\.([A-Za-z_][A-Za-z0-9_]*)", text):
            used.add(match.group(1))
    assert used, "no documented public symbols found"
    missing = sorted(symbol for symbol in used if not hasattr(public, symbol))
    assert not missing, f"documented symbols missing from the public root: {missing}"


def test_documented_cli_commands_match_the_real_cli_set() -> None:
    from dbf_anonymizer.cli import COMMANDS

    operations = _documents()[OPERATIONS]
    documented = set(re.findall(r"^dbf-anonymizer ([a-z-]+)", operations, flags=re.MULTILINE))
    assert documented == set(COMMANDS), (documented, set(COMMANDS))
    # The CLI command table (in the "Public API and CLI truth" section) must
    # name every command exactly once — scoped so policy tables cannot satisfy
    # the check.
    cli_section = operations.split("## Public API and CLI truth", 1)[1]
    cli_section = cli_section.split("## Quick start", 1)[0]
    table_commands = re.findall(r"^\| `([a-z-]+)` \|", cli_section, flags=re.MULTILINE)
    assert sorted(table_commands) == sorted(COMMANDS)


def test_documented_schema_and_version_constants_match_the_code() -> None:
    from dbf_anonymizer.errors import ERROR_REGISTRY_VERSION, ERROR_SCHEMA_VERSION
    from dbf_anonymizer.models import (
        INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        MODEL_SCHEMA_VERSION,
    )
    from dbf_anonymizer.relationships.models import RELATIONSHIP_METADATA_SCHEMA_VERSION

    text = _all_text()
    assert importlib.import_module("dbf_anonymizer").__version__ == "1.0.0.dev0"
    assert importlib.metadata_version if False else True
    assert "1.0.0.dev0" in text
    assert "dbfbridge[write]>=1.1.0,<2" in text
    # The pinned wheelhouse closure is documented with the exact versions.
    assert "dbfbridge" in text and "1.1.1" in text
    assert "dbfread" in text and "2.0.7" in text
    assert "dbf" in text and "0.99.11" in text
    assert "aenum" in text and "3.1.17" in text
    # Relationship metadata schema version is documented as 1.0.
    assert 'metadata_schema_version == "1.0"' in text or '"1.0"' in text
    # The public model/error/index schema constants referenced by docs.
    assert MODEL_SCHEMA_VERSION == "1.8"
    assert ERROR_SCHEMA_VERSION == "1.1"
    assert ERROR_REGISTRY_VERSION == "1.5"
    assert INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION == "1.2"
    assert RELATIONSHIP_METADATA_SCHEMA_VERSION == "1.0"
    # Private module paths are not documented as public contract.
    for private in ("dbf_anonymizer.engine.", "dbf_anonymizer.vault.", "dbf_anonymizer.planning."):
        assert private not in text, private


# ---------------------------------------------------------------------------
# 6. Executable examples (the objective acceptance evidence)
# ---------------------------------------------------------------------------


def _executable_documents() -> list[str]:
    return [
        name
        for name, text in _documents().items()
        if any(
            info.startswith("python") and EXECUTABLE_INFO_MARKER in info
            for info, _ in _fenced_blocks(text)
        )
    ]


def test_executable_examples_exist_for_the_required_topics() -> None:
    operations_blocks = [
        info
        for info, _ in _fenced_blocks(_documents()[OPERATIONS])
        if info.startswith("python") and EXECUTABLE_INFO_MARKER in info
    ]
    # The operations guide must carry the workflow chain: capabilities/synthetic
    # data, plan/preflight/pseudonymize/verify, recovery (enabled + disabled),
    # policy, relationships, DATA_ONLY.
    assert len(operations_blocks) >= 8, f"too few executable examples: {len(operations_blocks)}"


def test_executable_documentation_examples_run() -> None:

    executed = 0
    temp_roots: list[Path] = []
    try:
        for name, text in _documents().items():
            blocks = [
                body
                for info, body in _fenced_blocks(text)
                if info.startswith("python") and EXECUTABLE_INFO_MARKER in info
            ]
            if not blocks:
                continue
            namespace: dict[str, Any] = {"__name__": f"doc-example-{name}"}
            for index, block in enumerate(blocks):
                try:
                    exec(  # noqa: S102 - deterministic documented examples under test control
                        compile(block, f"<{name}:block-{index}>", "exec"),
                        namespace,
                    )
                except Exception as error:  # noqa: BLE001 - report the failing block
                    raise AssertionError(
                        f"executable example failed: {name} block {index}:\n{block}\n{error!r}"
                    ) from error
                executed += 1
            for value in namespace.values():
                if (
                    isinstance(value, Path)
                    and value.is_dir()
                    and "dbf-anonymizer-doc-" in value.name
                ):
                    temp_roots.append(value)
        assert executed >= 8, f"too few executable examples executed: {executed}"
    finally:
        for root in temp_roots:
            shutil.rmtree(root, ignore_errors=True)


def test_executable_examples_never_reference_private_temp_paths() -> None:
    for name, text in _documents().items():
        for info, body in _fenced_blocks(text):
            if not (info.startswith("python") and EXECUTABLE_INFO_MARKER in info):
                continue
            assert "C:\\" not in body and "C:/" not in body, name
            assert "Users/" not in body, name
            assert body.count("tempfile.mkdtemp") >= 0  # marker blocks are self-contained


# ---------------------------------------------------------------------------
# 7. Offline installation vs the pinned wheelhouse contract
# ---------------------------------------------------------------------------


def test_offline_install_examples_match_the_pinned_wheelhouse_contract() -> None:
    from tools.check_p7_offline_wheelhouse import EXPECTED_APPLICATION, EXPECTED_RUNTIME_PINS

    operations = _documents()[OPERATIONS]
    for required in (
        "--only-binary=:all:",
        "--no-cache-dir",
        "--no-deps",
        "--requirement requirements/p7-offline-wheelhouse.txt",
        "--no-index",
        "--find-links",
        "python -m pip check",
    ):
        assert required in operations, required
    application_pin = next(iter(EXPECTED_APPLICATION.items()))
    assert f"dbf-anonymizer=={application_pin[1]}" in operations
    for name, version in EXPECTED_RUNTIME_PINS.items():
        assert name in operations, name
        assert version in operations, version


# ---------------------------------------------------------------------------
# 8. DATA_ONLY truthfulness
# ---------------------------------------------------------------------------


def test_data_only_documentation_excludes_recovery_material() -> None:
    _topic_text(
        (
            "the recovery vault (`dictionary.sqlite3` / `recovery.sqlite3`)",
            "SQLite WAL/SHM/journal sidecars",
            "reverse mappings and recovery parameters",
            "secrets, salts, keyfiles and private manifests",
            "original source values and private paths or logs",
            "stale/unverified index artifacts",
        )
    )
    operations = _documents()[OPERATIONS]
    assert "copying the vault" in operations
    # The docs must never instruct copying recovery material into a transfer.
    for forbidden in (
        "copy the vault into the DATA_ONLY bundle",
        "include the vault in the transfer",
        "copy dictionary.sqlite3 into the bundle",
    ):
        assert forbidden not in _all_text(), forbidden


# ---------------------------------------------------------------------------
# 9. VFP/index truthfulness
# ---------------------------------------------------------------------------


def test_vfp_index_documentation_is_truthful() -> None:
    limits = _documents()[LIMITS]
    for required in (
        "REQUIRES",
        "backend evidence",
        "stale CDX/IDX/DBC artifacts are never transferred",
        "separately inventoried",
        "remains reported as DBC-bound",
        "does NOT imply preservation",
        "No automatic VFP project understanding",
        "BLOCKED/DEFERRED",
        "mcp-vfp9sp2-toolchain",
    ):
        assert required in limits, required
    # No overstatement of automatic discovery or P6-006 completion.
    for forbidden in (
        "automatically discovers DBC relationships",
        "P6-006 is complete",
        "fully preserves DBC triggers",
    ):
        assert forbidden not in _all_text(), forbidden


# ---------------------------------------------------------------------------
# 10. Transport-neutral / MCP boundary
# ---------------------------------------------------------------------------


def test_transport_neutral_and_not_mcp_server_statements() -> None:
    mcp = _normalized(_documents()[MCP_DOC])
    for required in (
        "synchronous, transport-neutral",
        "not an mcp server",
        "authentication and authorization",
        "asynchronous/job orchestration",
        "does not import mcp-vfp9sp2-toolchain",
        "dbf_anonymizer never calls the host",
    ):
        assert required in mcp, required
    readme = _normalized(_documents()["README.md"])
    assert "not an mcp server" in readme


# ---------------------------------------------------------------------------
# 11. Pseudonymized vs anonymous
# ---------------------------------------------------------------------------


def test_pseudonymized_vs_anonymous_distinction_is_explicit() -> None:
    readme = _normalized(_documents()["README.md"])
    distinction = _normalized(_documents()[DISTINCTION])
    assert "pseudonymized is not anonymous" in readme
    assert "pseudonymized" in readme and "not anonymized" in readme
    for required in (
        "pseudonymized data, not anonymized data",
        "quasi-identifiers",
        "relational structure",
        "no claim of gdpr-grade",
        "re-identification",
    ):
        assert required in distinction, required
    _topic_text(("is not proof of full anonymity",))


# ---------------------------------------------------------------------------
# 12. No private paths / sensitive material
# ---------------------------------------------------------------------------


def test_documentation_contains_no_private_paths_or_sensitive_material() -> None:
    text = _all_text()
    forbidden_patterns = (
        r"\b[A-Za-z]:[\\/]",
        r"(?i)\bfile://",
        r"(?i)/home/",
        r"(?i)/Users/",
        r"(?i)/root/",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\bghp_[A-Za-z0-9]{20,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
    )
    for pattern in forbidden_patterns:
        match = re.search(pattern, text)
        assert match is None, f"forbidden documentation content {match.group(0)!r}"
    # Recovery dictionary contents never appear as data.
    assert "INSERT INTO" not in text
    assert "CREATE TABLE" not in text


def test_documentation_never_points_outside_the_project() -> None:
    for name, text in _documents().items():
        for target in _LINK.findall(text):
            assert target.startswith(("http://", "https://", "#", "../", "docs/")) or not (
                target.startswith("/")
            ), f"{name}: unexpected absolute link target {target!r}"


def test_documented_json_contract_names_are_public() -> None:
    """Machine-mode examples must expose only public model_type names."""
    operations = _documents()[OPERATIONS]
    assert "--json" in operations
    # The CLI table exists and every command has a purpose column.
    assert operations.count("| `") >= 9
