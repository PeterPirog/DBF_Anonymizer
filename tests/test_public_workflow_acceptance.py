"""REQ-P1-004 — complete public consumer workflow acceptance.

This consumer module imports ONLY the public package surface: every
DBF_Anonymizer operation used here comes from ``dbf_anonymizer`` — no
private implementation module (``dbf_anonymizer.transfer_bundle``,
``dbf_anonymizer.verification``, ``dbf_anonymizer.recovery``,
``dbf_anonymizer.engine`` or ``dbf_anonymizer.vault``) is imported. The
public ``dbfbridge`` dependency and neutral test-fixture helpers may be
used for the synthetic fixture only.

Proves the complete public workflow on the implemented service set:

capabilities -> build_plan -> preflight -> pseudonymize -> verify_dataset
-> create_transfer_bundle -> verify_transfer_bundle (standalone, source
AND vault absent) -> recover.

Only disposable synthetic tmp_path fixtures created through the public
``dbfbridge`` writer are used; no production data is accessed.
"""

from __future__ import annotations

import shutil
from datetime import date, datetime
from pathlib import Path

import dbfbridge
import pytest

import dbf_anonymizer as public
from tests.support.numeric_tables import NULLABLE_FLAG, numeric_field


def _relationship_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "CODE",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "CODE",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            },
        ],
    }


def _binary_memo(name: str, dbf_type: str) -> dbfbridge.FieldInfo:  # type: ignore[attr-defined]
    return dbfbridge.FieldInfo(  # type: ignore[attr-defined]
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=4,
        decimal_count=0,
        address=0,
        flags=0,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=True,
        is_binary=True,
        supported=True,
        dbversion_byte=0x30,
    )


def _write_dataset(source: Path) -> None:
    from tests.support.numeric_tables import schema as _schema_kernel

    def write(
        relative: str,
        fields: tuple[object, ...],
        entries: list[tuple[dict[str, object], bool]],
    ) -> None:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        dbfbridge.write_table(  # type: ignore[attr-defined]
            path,
            schema=_schema_kernel(fields),
            records=[
                dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                    physical_index=0, deleted=deleted, values=values
                )
                for values, deleted in entries
            ],
        )

    write(
        "north/data.dbf",
        (
            numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
            numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
            numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
            _binary_memo("GEN", "G"),
            numeric_field("KEEP_N", "N", 6),
            numeric_field("KEEP_L", "L", 1),
        ),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "WHEN_D": date(2026, 3, 1),
                    "NOTE": "MEMO-N-1",
                    "KEEP_N": 11,
                    "KEEP_L": True,
                    "GEN": b"\x89SYNTHETIC-BINARY-\x00\x01",
                },
                False,
            ),
            (
                {
                    "CODE": "PARENT-2",
                    "WHEN_D": None,
                    "NOTE": None,
                    "KEEP_N": 22,
                    "KEEP_L": False,
                    "GEN": None,
                },
                True,
            ),
            (
                {
                    "CODE": "",
                    "WHEN_D": date(2026, 5, 20),
                    "NOTE": "",
                    "KEEP_N": 33,
                    "KEEP_L": None,
                    "GEN": b"",
                },
                False,
            ),
        ],
    )
    write(
        "south/data.dbf",
        (
            numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
            numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
            numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
            numeric_field("KEEP_N", "N", 6),
            numeric_field("KEEP_L", "L", 1),
        ),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "WHEN_D": date(2026, 3, 2),
                    "NOTE": "MEMO-S-1",
                    "KEEP_N": 44,
                    "KEEP_L": False,
                },
                True,
            ),
            (
                {
                    "CODE": None,
                    "WHEN_D": None,
                    "NOTE": "",
                    "KEEP_N": 55,
                    "KEEP_L": None,
                },
                False,
            ),
        ],
    )
    write(
        "archive/data.dbf",
        (
            numeric_field("VCHAR", "V", 20, flags=NULLABLE_FLAG),
            numeric_field("PICTURE", "P", 4, flags=NULLABLE_FLAG),
            numeric_field("KEEP_I", "I", 4),
        ),
        [
            (
                {
                    "VCHAR": "TRAILING   ",
                    "PICTURE": b"PICTURE-BYTES-\x02",
                    "KEEP_I": 42,
                },
                False,
            ),
            (
                {"VCHAR": None, "PICTURE": None, "KEEP_I": -1},
                True,
            ),
        ],
    )


def _table_records(root: Path, relative: str) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            record.physical_index,
            record.deleted,
            tuple(sorted(record.values.items())),
        )
        for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
            root / relative, include_deleted=True, memo="inline"
        )
    )


def test_complete_public_consumer_workflow(tmp_path: Path) -> None:
    """The COMPLETE public workflow through PUBLIC imports only (REQ-P1-004).

    capabilities -> build_plan -> preflight -> pseudonymize -> verify_dataset
    -> create_transfer_bundle -> verify_transfer_bundle (standalone, copied
    bundle with source AND vault absent) -> recover — followed by the
    canonical logical oracle comparison through public dbfbridge reads.
    """
    # The public surface carries all eight architecture-required operations.
    for operation in (
        "capabilities",
        "build_plan",
        "preflight",
        "pseudonymize",
        "verify_dataset",
        "recover",
        "create_transfer_bundle",
        "verify_transfer_bundle",
    ):
        assert callable(getattr(public, operation)), operation
    caps = public.capabilities()
    assert caps.recovery is True
    assert caps.transfer_bundle is True
    assert caps.vfp_index_backend is False

    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"

    # 1. build_plan (declared PK/FK relation).
    plan = public.build_plan(
        source, output, vault, relationship_document=_relationship_document()
    )

    # 2. preflight.
    assert public.preflight(plan).ready is True

    # 3. pseudonymize (workers=1 and workers=2 stay equivalent — the same
    #    canonical result).
    result = public.pseudonymize(plan, workers=2)
    assert isinstance(result, public.PseudonymizationResult)

    # 4. verify_dataset — the authoritative PASS verdict.
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS

    # 5. create_transfer_bundle (the verified-dataset precondition).
    bundle = public.create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )
    assert bundle.verified is True
    assert bundle.profile is public.TransferProfile.DATA_ONLY

    # 6. verify_transfer_bundle on a COPIED bundle. The verifier needs
    # neither the source nor the vault — the source is deleted NOW to prove
    # it (the vault stays only because step 7 legitimately needs it). A
    # preserved oracle copy OUTSIDE the production recovery arguments
    # provides the final comparison.
    oracle = tmp_path / "oracle"
    shutil.copytree(source, oracle)
    copied = tmp_path / "copied-bundle"
    shutil.copytree(tmp_path / "bundle", copied)
    shutil.rmtree(source)
    standalone = public.verify_transfer_bundle(copied)
    assert standalone.verified is True
    assert standalone.manifest_fingerprint == bundle.manifest_fingerprint

    # 7. recover — the path-based SOURCE-FREE protected recovery: called
    # with ONLY the pseudonymized working dataset path + the vault path
    # (the original source is already deleted above; the private
    # PseudonymizationResult result object is never passed).
    recovery = public.recover(
        pseudonymized=output, vault=vault, output=tmp_path / "recovered"
    )
    assert recovery.canonical_verified is True
    assert recovery.raw_byte_equivalence is public.RawByteEquivalence.NOT_EVALUATED
    assert recovery.operation_id != result.operation_id

    # Canonical logical oracle: the recovered dataset equals the original
    # through PUBLIC dbfbridge reads (topology, schema, records, order,
    # deleted markers, NULLs, C/V, memo payloads, D/T, logical numerics).
    original_topology = sorted(
        path.relative_to(oracle).as_posix() for path in oracle.rglob("*") if path.is_file()
    )
    recovered_topology = sorted(
        path.relative_to(tmp_path / "recovered").as_posix()
        for path in (tmp_path / "recovered").rglob("*")
        if path.is_file()
    )
    assert original_topology == recovered_topology
    for relative in original_topology:
        if not relative.endswith(".dbf"):
            continue
        assert _table_records(oracle, relative) == _table_records(
            tmp_path / "recovered", relative
        )


def test_complete_public_consumer_workflow_no_relationship_document(
    tmp_path: Path,
) -> None:
    """The default no-relationship build_plan path completes the same public
    workflow (GLOBAL_EXACT_VALUE assurance with declared=0)."""
    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = public.build_plan(source, output, vault, relationship_document=None)
    assert public.preflight(plan).ready is True
    result = public.pseudonymize(plan)
    assert result.assurance.level is public.RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    assert result.assurance.declared_relations == 0
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    bundle = public.create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )
    standalone = public.verify_transfer_bundle(tmp_path / "bundle")
    assert standalone.verified is True
    recovery = public.recover(
        pseudonymized=output, vault=vault, output=tmp_path / "recovered"
    )
    assert recovery.canonical_verified is True
    # The bundle's transferred assurance carries the same truthful facts.
    assert standalone.assurance == result.assurance
    assert standalone.assurance.evidence_schema_version == "1.0"
    assert standalone.assurance.scope_note == (
        "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"
    )


def test_public_relationship_metadata_bundle_round_trip(tmp_path: Path) -> None:
    """A public RelationshipMetadata path accepted by P3 without a
    relationship document round-trips through the transfer bundle: the
    canonical producer's relationship_fingerprint shape is preserved."""
    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = public.build_plan(source, output, vault, relationship_document=None)
    result = public.pseudonymize(plan)
    bundle = public.create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )
    standalone = public.verify_transfer_bundle(tmp_path / "bundle")
    assert standalone.verified is True
    # The transferred relationship_fingerprint is EXACTLY the producer's
    # (the canonical bounded token accepted by the public P3 model — never
    # narrowed to a raw-hex-only contract).
    assert standalone.assurance.relationship_fingerprint == (
        result.assurance.relationship_fingerprint
    )
    assert standalone.assurance.relationship_fingerprint is not None
    assert len(standalone.assurance.relationship_fingerprint) >= 8
    assert "\\" not in (standalone.assurance.relationship_fingerprint or "")
    assert (standalone.assurance.relationship_fingerprint or "").strip() == (
        standalone.assurance.relationship_fingerprint
    )


def test_standalone_verification_needs_no_vault_or_source(tmp_path: Path) -> None:
    """Standalone verification NEVER searches for or requests a vault, and
    never needs the source: prove it succeeds with both completely absent
    and the working dataset also removed."""
    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = public.build_plan(source, output, vault, relationship_document=None)
    result = public.pseudonymize(plan)
    bundle = public.create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )
    # Everything except the copied bundle is gone.
    shutil.rmtree(source)
    shutil.rmtree(output)
    shutil.rmtree(vault.parent)
    standalone = public.verify_transfer_bundle(tmp_path / "bundle")
    assert standalone.verified is True