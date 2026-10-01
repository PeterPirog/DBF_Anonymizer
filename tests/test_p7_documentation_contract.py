"""REQ-P7-009 documentation contract: English-first, truthful, executable.

Proves the user documentation objectively:

1. every required REQ-P7-009 topic is covered by version-controlled English
   docs (semantic multi-marker coverage, not single-sentence matching);
2. every relative documentation link resolves and every doc is reachable from
   the README;
3. documented public Python symbols actually exist on the public package root;
4. documented CLI command names match the real CLI command set exactly and
   every command advertises its ``--json`` machine mode;
5. every published version/schema value in the docs matches the actual
   package metadata, the actual pyproject.toml requirement and the actual
   public code constants (labelled documentation values, compared exactly);
6. fenced blocks marked ``python p7-009-exec`` are real executable acceptance
   examples: they are extracted deterministically and run against synthetic
   task-owned TEMP data. Within ONE document the blocks are intentionally
   cumulative: the first block of a document bootstraps that document's
   namespace (including its synthetic work root) and every later block of the
   same document reuses that namespace; each document starts fresh;
7. offline-install examples are real, repository-consistent commands (real
   PowerShell copy/venv commands, pinned wheelhouse closure, no network);
8. DATA_ONLY documentation enumerates the excluded recovery material and
   never instructs copying the vault into a transfer;
9. index/VFP/DBC documentation stays truthful: DBC-bound SOURCE facts are
   reported without claiming DBC preservation in standalone output, the
   standalone core requires no VFP/COM/subprocess/network and never scans for
   VFP, the injected ``IndexBackend`` capability is not denied, P7-004 stays
   the no-HTTP/no-Git/no-install/no-download guarantee, and the completed
   P6-006 external VFP metadata contract is documented truthfully
   (package-owned, shipped schema, producer-independent, host-injected,
   subject to the implemented per-claim provenance/authority/assurance/
   verification rules — no automatic DBC discovery);
10. DBF_Anonymizer is described as transport-neutral and NOT an MCP server;
11. the pseudonymized-vs-anonymous distinction is present and explicit;
12. docs contain no private paths, secrets or production-data instructions;
13. English-first is proven structurally: explicit English primary headings,
    explicit English operational/security terms, and no Polish or Chinese
    user-facing markers in the P7-009 user documents.

The examples use synthetic fixtures only; the harness never touches
production datasets.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import re
import shutil
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"
DOCUMENT_NAMES = (
    "README.md",
    "docs/operations.md",
    "docs/limits-and-integrity.md",
    "docs/external-vfp-metadata-contract.md",
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

#: The P7-009 user documents (new in this requirement) whose primary language
#: evidence is proven structurally.
P7_009_DOCUMENT_NAMES = (
    "README.md",
    "docs/operations.md",
    "docs/limits-and-integrity.md",
    "docs/mcp-integration.md",
    "docs/threat-model.md",
    "docs/pseudonymization-vs-anonymization.md",
)

#: Required explicit English primary (H1) headings of the P7-009 documents.
REQUIRED_ENGLISH_PRIMARY_HEADINGS = {
    "README.md": "DBF_Anonymizer",
    "docs/operations.md": "DBF_Anonymizer operations guide",
    "docs/limits-and-integrity.md": "Index, VFP and DBC limitations (truthful capability boundaries)",
    "docs/mcp-integration.md": "mcp-vfp9sp2-toolchain consumer integration",
    "docs/threat-model.md": "Threat model",
    "docs/pseudonymization-vs-anonymization.md": "Pseudonymized is not anonymous",
}

#: Required explicit English operational/security vocabulary across the
#: P7-009 user documents (structural anchor, not language detection).
REQUIRED_ENGLISH_OPERATIONAL_TERMS = (
    "internal-network offline installation",
    "one vault per dataset",
    "policy configuration",
    "relationship configuration",
    "pseudonymization",
    "verification",
    "recovery",
    "DATA_ONLY transfer bundles",
    "recovery vault",
    "threat model",
    "trust boundaries",
    "pseudonymized is not anonymous",
    "not an MCP server",
)

#: Unambiguous Polish user-facing words (word-bounded). The guard is a
#: regression tripwire against accidental Polish primary documentation, not a
#: language-detection engine.
POLISH_USER_MARKERS = re.compile(
    r"\b(?:oraz|dla|jest|nie|ktory|ktora|ktore|poniewaz|przez|tylko|danych|nalezy)"
    r"\b",
    re.IGNORECASE,
)

#: Chinese (Han) script ranges — any match fails the English-first guard.
CJK_MARKER = re.compile(r"[\u3400-\u9fff\uf900-\ufaff]")

#: Negation tokens that legitimately scope a mention of a forbidden claim.
NEGATION_TOKEN = re.compile(r"\b(?:not|no|never|cannot|without)\b", re.IGNORECASE)

#: Claims that DBC binding survives into the OUTPUT (contradicts REQ-P6-005:
#: fresh Direct Write output is standalone data). Only negated mentions are
#: truthful; every match must carry a negation token in the preceding window.
DBC_OUTPUT_PRESERVATION_CLAIMS = (
    r"\bpreserv\w*[^.\n]{0,30}\boutput\b",
    r"\bbinding[^.\n]{0,30}\bpreserv\w*",
    r"\bpreserv\w*[^.\n]{0,30}\b(?:source\s+)?(?:dbc\s+|database[-\s]container\s+)*binding\b",
    r"\bdbc[-\s]bound\s+output\b",
    r"\boutput\b[^.\n]{0,30}\bdbc[-\s]bound\b",
    r"\b(?:keeps?|retains?|carries?|includes?)\s+(?:the\s+)?(?:source\s+)?"
    r"(?:dbc\s+|database[-\s]container\s+)*(?:binding|backlink)",
)

#: False deterministic pseudonym claims (contradict REQ-P2-004: text
#: pseudonyms use cryptographically secure randomness, fresh vaults produce
#: independent sets, same vault reuses stored mappings). Only negated
#: mentions are truthful; blanket "deterministic" claims about pseudonym
#: generation are architecturally false.
#: Patterns are scoped to avoid matching correctly negated/qualified statements.
DETERMINISTIC_PSEUDONYM_CLAIMS = (
    r"transforms?\s+values?\s+deterministic(?:ally)?\s+(?:and\s+reversibly)?",
    r"deterministic(?:ally)?\s+(?:derives?|generates?|produces?)\s+(?:text\s+)?pseudonyms?",
    r"pseudonyms?\s+are\s+deterministic(?:ally)?\s+(?:derived|generated|produced)\s+from",
    r"same\s+(?:source\s+)?value\s+(?:always\s+)?produces\s+the\s+same\s+pseudonym\s+(?:across|in)\s+fresh",
    r"predictably\s+derived\s+from\s+(?:the\s+)?(?:original\s+)?value",
    r"deterministic\s+mapping\s+from\s+original\s+(?:to\s+)?pseudonym",
    r"fresh\s+vault\s+(?:produces?|yields?|gives?)\s+the\s+same\s+pseudonym",
)

#: Unconditional no-subprocess/no-process guarantees (contradict the injected
#: IndexBackend capability; P7-004 is no-HTTP/no-Git/no-install/no-download,
#: never a blanket process prohibition).
UNCONDITIONAL_SUBPROCESS_CLAIMS = (
    r"no\s+subprocess(?:es)?\s+execution\s+during\s+operation",
    r"blocks?\s+network\s+and\s+process\s+boundaries",
    r"\bnever\s+start\w*\s+subprocess\w*\s+during\s+operation\b",
    r"\bno\s+subprocess(?:es)?\s+(?:ever|at\s+any\s+point)\b",
)

#: Blanket "the product never launches/reads VFP" claims (too broad: the
#: injected backend may perform the authoritative VFP work).
ABSOLUTE_VFP_LAUNCH_CLAIMS = (
    r"\bdbf[-_]anonymizer\s+never\s+launch\w*\s+vfp\b",
    r"\bdbf[-_]anonymizer\s+never\s+reads?\s+vfp\b",
    r"\bnever\s+launch\w*\s+vfp\b",
)

#: Wordings that deny the legitimate injected backend capability or imply
#: automatic VFP installation discovery.
BACKEND_CAPABILITY_DENIALS = (
    r"backend\s+(?:must\s+not|may\s+not|cannot|can\s*not|never)[^.\n]{0,40}\b"
    r"(?:launch|start|run|invoke|perform)\b[^.\n]{0,40}\bvfp\b",
    r"no\s+vfp\s+(?:work|execution|rebuild)\s+(?:is\s+)?(?:ever\s+)?permitted",
)

AUTOMATIC_VFP_DISCOVERY_CLAIMS = (
    r"\bautomatic(?:ally)?\s+(?:vfp|visual\s+foxpro)\s+"
    r"(?:installation\s+)?(?:discovery|discovering|detection|search|scanning)\b",
    r"\b(?:scans?|search(?:es)?|probes?|discovers?)\s+(?:the\s+|for\s+|any\s+)*"
    r"(?:machine|program\s+files|installed\s+vfp)[^.\n]{0,40}\bvfp\b",
)


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


def _assert_no_unnegated_claim(text: str, pattern: str, *, label: str) -> None:
    """Every regex match of *pattern* must carry a negation token in the same
    sentence (within the 40 characters before it, never crossing a sentence
    or line boundary), so only negated (truthful) mentions of the forbidden
    claim remain in the documentation."""
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        prefix = text[max(0, match.start() - 40) : match.start()]
        boundary = max(prefix.rfind("."), prefix.rfind("!"), prefix.rfind("?"), prefix.rfind("\n"))
        if boundary != -1:
            prefix = prefix[boundary + 1 :]
        if not NEGATION_TOKEN.search(prefix):
            raise AssertionError(
                f"unnegated forbidden documentation claim ({label}): {match.group(0)!r}"
            )


def _forbid_unnegated_claims(patterns: tuple[str, ...], *, label: str) -> None:
    text = _all_text()
    for pattern in patterns:
        _assert_no_unnegated_claim(text, pattern, label=label)


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
            "EXTERNAL_VFP_METADATA",
            "CONTRACT_AUTHORITATIVE",
            "EXACT_VALUE",
            "REVERSIBLE_BIJECTIVE",
            "PRIMARY",
            "FOREIGN",
            "no automatic DBC relationship discovery",
            "preflight",
            "external-vfp-metadata-contract.md",
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
            "the protected mapping material",
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
            "external-vfp-metadata-contract.md",
            "external_metadata_schema_version",
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
    """Structural English-first evidence (no language-detection dependency):

    (a) no Polish diacritics and no Chinese characters anywhere in the user
        documentation (UTF-8 stays supported; the guard is character-class
        based, deterministic and dependency-free);
    (b) every P7-009 user document opens with the required explicit English
        primary heading;
    (c) every heading of a P7-009 user document is ASCII (English);
    (d) required operational/security vocabulary is explicit English;
    (e) no known Polish user-facing marker appears in a P7-009 document.
    """
    documents = _documents()
    polish_diacritics = set("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
    for name, text in documents.items():
        found = sorted(set(text) & polish_diacritics)
        assert not found, f"{name} contains Polish diacritics: {found}"
        cjk = CJK_MARKER.search(text)
        assert cjk is None, f"{name} contains a Chinese character: {cjk.group(0)!r}"

    for name in P7_009_DOCUMENT_NAMES:
        primary = next(
            (line for line in documents[name].splitlines() if line.startswith("# ")),
            None,
        )
        assert primary is not None, f"{name} has no primary (H1) heading"
        assert primary[2:] == REQUIRED_ENGLISH_PRIMARY_HEADINGS[name], (
            f"{name}: unexpected primary heading {primary!r}"
        )

    for name in P7_009_DOCUMENT_NAMES:
        headings = [line for line in documents[name].splitlines() if re.match(r"^#{1,6} ", line)]
        assert headings, f"{name} has no section headings"
        for heading in headings:
            non_ascii_letters = sorted({ch for ch in heading if ch.isalpha() and not ch.isascii()})
            assert not non_ascii_letters, (
                f"{name}: non-English letters in heading {heading!r}: {non_ascii_letters}"
            )

    aggregated = _normalized("\n".join(documents[name] for name in P7_009_DOCUMENT_NAMES))
    missing = [
        term for term in REQUIRED_ENGLISH_OPERATIONAL_TERMS if _normalized(term) not in aggregated
    ]
    assert not missing, f"required English operational terms missing: {missing}"

    for name in P7_009_DOCUMENT_NAMES:
        marker = POLISH_USER_MARKERS.search(documents[name])
        assert marker is None, f"{name} contains a Polish user-facing marker: {marker.group(0)!r}"


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
    """Documentation and code agree on every published version/schema value.

    Each comparison parses the LABELLED documented value from the user docs
    and compares it EXACTLY to the actual installed package metadata, the
    actual pyproject.toml runtime requirement or the actual public code
    constant — never a code constant against a hardcoded test literal.
    """
    public = importlib.import_module("dbf_anonymizer")
    from dbf_anonymizer.relationships.models import RELATIONSHIP_METADATA_SCHEMA_VERSION

    # A. Package version: installed public metadata vs the labelled
    # application wheel pin published by the offline installation guide.
    package_version = importlib.metadata.version("dbf-anonymizer")
    assert package_version == public.__version__
    operations = _documents()[OPERATIONS]
    application_pins = re.findall(r"dbf-anonymizer==([^\s`|)\"]+)", operations)
    assert application_pins, "operations.md must publish the application wheel pin"
    assert set(application_pins) == {package_version}, application_pins

    # B. Runtime dependency range: pyproject.toml vs the labelled documented
    # runtime boundary in limits-and-integrity.md and the README.
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    actual_requirement = next(
        (
            requirement
            for requirement in pyproject["project"]["dependencies"]
            if requirement.startswith("dbfbridge")
        ),
        None,
    )
    assert actual_requirement is not None, (
        "pyproject.toml must declare the dbfbridge[write] runtime dependency"
    )
    limits = _documents()[LIMITS]
    readme = _documents()["README.md"]
    for name, text in (("limits-and-integrity.md", limits), ("README.md", readme)):
        documented_suffixes = re.findall(r"dbfbridge\[write\]([^\s`|)\"]+)", text)
        assert documented_suffixes, f"{name} must publish the runtime dependency range"
        documented_requirements = {f"dbfbridge[write]{suffix}" for suffix in documented_suffixes}
        assert documented_requirements == {actual_requirement}

    # C. Relationship metadata schema: labelled documented value vs code.
    # The boundary is scoped so the DISTINCT external envelope field
    # (external_metadata_schema_version) is verified on its own below.
    relationship_labels = re.findall(
        r"(?<!external_)metadata_schema_version\s*==\s*\"([^\"]+)\"", operations
    )
    assert relationship_labels == [RELATIONSHIP_METADATA_SCHEMA_VERSION]
    external_labels = re.findall(
        r"external_metadata_schema_version\s*==\s*\"([^\"]+)\"", operations
    )
    from dbf_anonymizer.relationships.external_metadata import (  # noqa: PLC0415
        EXTERNAL_METADATA_SCHEMA_VERSION,
    )

    assert external_labels == [EXTERNAL_METADATA_SCHEMA_VERSION]

    # D. Public model / error / index-protocol schemas: the docs that publish
    # them as user contract carry labelled values compared to the code
    # constants. INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION is documented with the
    # VFP_INDEXED backend-evidence requirement in limits-and-integrity.md.
    models_doc = (REPO_ROOT / "docs/public-models-1.0.md").read_text(encoding="utf-8")
    model_labels = re.findall(r"schema_version\s*=\s*\"([^\"]+)\"", models_doc)
    assert model_labels == [public.MODEL_SCHEMA_VERSION]

    errors_doc = (REPO_ROOT / "docs/errors-1.0.md").read_text(encoding="utf-8")
    error_labels = re.findall(r"public error payload schema\s*\(`([^`]+)`\)", errors_doc)
    assert error_labels == [public.ERROR_SCHEMA_VERSION]
    registry_labels = re.findall(r"error-code registry\s*\(`([^`]+)`\)", errors_doc)
    assert registry_labels == [public.ERROR_REGISTRY_VERSION]

    index_labels = re.findall(r"index-backend protocol schema version\s+`([0-9][^`]*)`", limits)
    assert index_labels == [public.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION]

    # E. The CLI command set is proven separately (exact COMMANDS comparison)
    # and the relative links separately (exact resolution); this test covers
    # only the published version/schema labels.

    # Private module paths are not documented as public contract.
    text = _all_text()
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


def test_executable_marker_blocks_share_one_cumulative_namespace() -> None:
    """The marker blocks are intentionally cumulative within one document
    namespace, and the harness documents that actual design: the FIRST
    p7-009-exec block of a document bootstraps that document's namespace
    (including its own synthetic ``tempfile.mkdtemp`` work root) and every
    later block of the same document reuses that namespace instead of
    creating new temporaries. Every block stays free of private temp paths.
    """
    for name, text in _documents().items():
        blocks = [
            body
            for info, body in _fenced_blocks(text)
            if info.startswith("python") and EXECUTABLE_INFO_MARKER in info
        ]
        if not blocks:
            continue
        first_block, later_blocks = blocks[0], blocks[1:]
        assert 'tempfile.mkdtemp(prefix="dbf-anonymizer-doc-")' in first_block, (
            f"{name}: the first marker block must bootstrap the document namespace"
        )
        for index, block in enumerate(later_blocks, start=1):
            assert "tempfile.mkdtemp" not in block, (
                f"{name}: block {index} must reuse the document namespace, not create a new temp root"
            )
        for block in blocks:
            assert "C:\\" not in block and "C:/" not in block, name
            assert "Users/" not in block, name


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
    ):
        assert required in operations, required
    # The copy step is a REAL Windows PowerShell command (never prose).
    assert 'Copy-Item -Path "dist\\*.whl" -Destination "WHEELHOUSE"' in operations
    assert "copy dist\\*.whl into WHEELHOUSE" not in operations
    # The manifest and checker referenced by the commands exist in the repo.
    assert (REPO_ROOT / "requirements" / "p7-offline-wheelhouse.txt").is_file()
    assert (REPO_ROOT / "tools" / "check_p7_offline_wheelhouse.py").is_file()
    # The documented pinned-closure table equals the tool constants exactly.
    closure_section = operations.split("The exact pinned runtime closure is:", 1)[1]
    closure_section = closure_section.split("Step 3", 1)[0]
    closure_rows = re.findall(
        r"^\| `?([A-Za-z0-9._-]+)`? \| ([0-9][^|]+) \|$",
        closure_section,
        flags=re.MULTILINE,
    )
    parsed_pins: dict[str, str] = {}
    for name, cell in closure_rows:
        version = re.match(r"([0-9][A-Za-z0-9.]*)", cell.strip())
        assert version is not None, f"unparsable pinned version for {name}: {cell!r}"
        parsed_pins[name] = version.group(1)
    assert parsed_pins == EXPECTED_RUNTIME_PINS
    # The application wheel is the DBF_Anonymizer distribution itself, at the
    # actual installed package metadata version.
    application_version = importlib.metadata.version("dbf-anonymizer")
    assert EXPECTED_APPLICATION == {"dbf-anonymizer": application_version}
    assert f"dbf-anonymizer=={application_version}" in operations
    # The internal install uses the venv interpreter with --no-index and
    # --find-links only, and verifies the installed metadata with pip check.
    assert (
        "INTERNAL_VENV\\Scripts\\python.exe -m pip install --no-index "
        "--find-links WHEELHOUSE" in operations
    )
    assert "INTERNAL_VENV\\Scripts\\python.exe -m pip check" in operations
    # The Windows-specific command blocks are explicitly labelled PowerShell.
    powershell_blocks = [
        info for info, _ in _fenced_blocks(operations) if info.startswith("powershell")
    ]
    assert len(powershell_blocks) >= 2, powershell_blocks


# ---------------------------------------------------------------------------
# 8. DATA_ONLY truthfulness
# ---------------------------------------------------------------------------


def test_data_only_documentation_excludes_recovery_material() -> None:
    _topic_text(
        (
            "the recovery vault (`dictionary.sqlite3` / `recovery.sqlite3`)",
            "SQLite WAL/SHM/journal sidecars",
            "the protected mapping material (the authoritative original → pseudonym",
            "mappings and any reverse lookup) and recovery parameters",
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
    # Mapping terminology stays technically correct: the vault stores the
    # authoritative FORWARD mappings (original → pseudonym) and recovery
    # derives the reverse lookup — "original → pseudonym" is never described
    # as a "reverse mapping" (in any phrasing or arrow form), and no real
    # mapping values are exposed.
    terminology = re.compile(
        r"reverse\s+mappings?[^.\n]{0,30}\boriginal\s+(?:value\s+)?(?:→|->|=>)",
        re.IGNORECASE,
    )
    match = terminology.search(_all_text())
    assert match is None, f"forbidden mapping-direction terminology: {match.group(0)!r}"


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
        # The completed P6-006 external metadata contract is documented
        # truthfully as package-owned and host-injected (present tense).
        "external-vfp-metadata-contract.md",
        "existing public synchronous planning boundary",
        "does NOT recreate source DBC semantics",
        "does NOT by itself prove that an output CDX/IDX",
        "authoritative backend rebuild/verification evidence",
        "mcp-vfp9sp2-toolchain",
    ):
        assert required in limits, required
    # No overstatement of automatic discovery, DBC preservation — and the
    # obsolete blocked narrative must never return.
    for forbidden in (
        "automatically discovers DBC relationships",
        "fully preserves DBC triggers",
        # Obsolete narrative restored (P6-006 is complete on main):
        "remains BLOCKED/DEFERRED",
    ):
        assert forbidden not in _all_text(), forbidden


def test_external_metadata_documentation_matches_production() -> None:
    """The external VFP metadata documentation cannot drift from production.

    The documented external schema version and resource identity must equal
    the ACTUAL production constants (never a hardcoded test literal), the
    public loader must successfully load the shipped schema, and the
    wheel-shipped schema resource must exist.
    """
    from importlib.resources import files

    from dbf_anonymizer.relationships.external_metadata import (  # noqa: PLC0415
        EXTERNAL_METADATA_SCHEMA_RESOURCE,
        EXTERNAL_METADATA_SCHEMA_VERSION,
        load_external_metadata_schema,
    )

    contract_doc = _documents()["docs/external-vfp-metadata-contract.md"]
    documented_versions = set(
        re.findall(r"external VFP metadata schema version [`\"](\d+\.\d+)[`\"]", contract_doc)
    )
    assert documented_versions == {EXTERNAL_METADATA_SCHEMA_VERSION}, documented_versions
    documented_resources = set(
        re.findall(r"(schemas/external-vfp-metadata-[\w.-]+\.schema\.json)", contract_doc)
    )
    assert EXTERNAL_METADATA_SCHEMA_RESOURCE in documented_resources, documented_resources
    schema = load_external_metadata_schema()
    assert schema["x-contract-schema-version"] == EXTERNAL_METADATA_SCHEMA_VERSION
    # The wheel-shipped resource exists inside the installed package tree.
    package_files = files("dbf_anonymizer")
    shipped = package_files / "schemas" / EXTERNAL_METADATA_SCHEMA_RESOURCE.removeprefix("schemas/")
    assert shipped.is_file(), EXTERNAL_METADATA_SCHEMA_RESOURCE


def test_dbc_source_and_output_truth_semantics() -> None:
    """REQ-P6-005 truth semantics, positive and negative.

    Positive: a DBC-bound SOURCE stays truthfully reported as DBC-bound in
    the source inventory/plan/public source facts, fresh Direct Write output
    is standalone data unless authoritative higher-level metadata is
    injected, the standalone output schema does NOT retain the source DBC
    binding/backlink, DBC rules/triggers/relations/views/procedures are never
    invented or rewritten, and DATA_ONLY omits DBC/DCT/DCX plus stale
    CDX/IDX artifacts.

    Negative: no sentence may claim (unnegated) that DBC binding is preserved
    in the output, that the output remains/keeps DBC-bound, or that the
    output retains the DBC binding/backlink — regardless of exact phrasing.
    """
    limits = _normalized(_documents()[LIMITS])
    for required in (
        "reported as DBC-bound in the source inventory",
        "STANDALONE data unless authoritative higher-level metadata is injected",
        "does NOT retain the source DBC binding",
        "does NOT imply preservation",
        "DBC rules, triggers, persistent relations, views or stored procedures",
        "invents, rewrites or copies none of them",
        "omits DBC/DCT/DCX and stale CDX/IDX artifacts",
    ):
        assert _normalized(required) in limits, required
    _forbid_unnegated_claims(DBC_OUTPUT_PRESERVATION_CLAIMS, label="DBC output preservation")


def test_subprocess_and_vfp_boundary_semantics() -> None:
    """The VFP/subprocess boundary is stated with the required precision.

    Positive: default standalone operation (index_backend=None) requires no
    VFP, no COM, starts no VFP/index subprocess and requires no network;
    import/capability discovery instantiates no COM, discovers no VFP and
    starts no subprocess; the injected IndexBackend may perform the
    authoritative VFP work outside the standalone core boundary; P7-004 is
    exactly no-HTTP/no-Git/no-package-installation/no-dependency-download;
    the core never scans the machine for VFP.

    Negative: unconditional "no subprocess during operation" guarantees,
    blanket "never launches VFP" claims, backend-capability denials and
    automatic-VFP-discovery implications are rejected.
    """
    limits = _normalized(_documents()[LIMITS])
    for required in (
        "require no VFP, no COM",
        "start no VFP/index subprocess",
        "contact no network",
        "never scan the machine for VFP installations",
        "does not instantiate COM",
        "does not discover or search for VFP",
        "starts no subprocesses",
        "no import-time VFP backend dependency",
        "explicitly injects",
        "may perform the authoritative VFP work",
        "outside the standalone core boundary",
        "no HTTP",
        "no Git",
        "no package installation",
        "no dependency download",
    ):
        assert _normalized(required) in limits, required
    # The P7-004 guarantee must NOT be stated as a blanket process ban, and
    # the product must NOT be described as never launching VFP at all.
    for forbidden in UNCONDITIONAL_SUBPROCESS_CLAIMS:
        assert re.search(forbidden, _all_text(), flags=re.IGNORECASE) is None, forbidden
    for forbidden in ABSOLUTE_VFP_LAUNCH_CLAIMS:
        assert re.search(forbidden, _all_text(), flags=re.IGNORECASE) is None, forbidden
    _forbid_unnegated_claims(BACKEND_CAPABILITY_DENIALS, label="injected backend capability denial")
    _forbid_unnegated_claims(AUTOMATIC_VFP_DISCOVERY_CLAIMS, label="automatic VFP discovery")


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
# 11b. Pseudonym allocation truthfulness (REQ-P2-004 / REQ-P7-009)
# ---------------------------------------------------------------------------


def test_pseudonym_allocation_documentation_is_truthful() -> None:
    """REQ-P2-004 / REQ-P7-009 truth semantics for text pseudonym allocation.

    Positive: the documentation must explicitly state:
    - cryptographically secure/random text pseudonym allocation on first creation
    - fresh-vault independence / non-repeatability semantics
    - same-compatible-vault mapping stability and reuse
    - reversibility through the protected vault (not deterministic derivation)

    Negative: the documentation must NOT contain unnegated blanket claims such as:
    - "transforms values deterministically"
    - "deterministically derives pseudonyms from original values"
    - "the same source value always produces the same pseudonym across fresh vaults"
    - "predictably derived from the original value"
    """
    distinction = _documents()[DISTINCTION]

    # Positive required markers
    for required in (
        "cryptographically secure randomness",
        "fresh compatible vault",
        "independent pseudonym set",
        "same compatible vault",
        "stable and reused consistently",
        "reversibility through the protected vault",
        "not guaranteed to receive the same pseudonym",
    ):
        assert _normalized(required) in _normalized(distinction), (
            f"required pseudonym allocation truth missing: {required!r}"
        )

    # Negative: forbid unnegated false deterministic claims
    _forbid_unnegated_claims(DETERMINISTIC_PSEUDONYM_CLAIMS, label="false deterministic pseudonym")


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
    repo_root = REPO_ROOT.resolve()
    for name, text in _documents().items():
        base = (REPO_ROOT / name).parent
        for target in _LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue  # pure in-page anchor
            resolved = (base / path_part).resolve()
            assert repo_root == resolved or repo_root in resolved.parents, (
                f"{name}: link {target!r} escapes the repository root"
            )


def test_documented_json_contract_names_are_public() -> None:
    """Machine-mode documentation exposes the versioned JSON contract: the
    CLI command table must name exactly the real command set and every
    command must advertise its ``--json`` machine mode."""
    from dbf_anonymizer.cli import COMMANDS

    operations = _documents()[OPERATIONS]
    cli_section = operations.split("## Public API and CLI truth", 1)[1]
    cli_section = cli_section.split("## Quick start", 1)[0]
    command_rows = re.findall(
        r"^\| `([a-z-]+)` \|([^|]*)\|([^|]*)\|$",
        cli_section,
        flags=re.MULTILINE,
    )
    assert {name for name, _, _ in command_rows} == set(COMMANDS)
    for name, _purpose, machine_mode in command_rows:
        assert "--json" in machine_mode, f"{name} must advertise --json machine mode"
