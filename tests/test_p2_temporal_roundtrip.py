"""Real DBF/FPT reversible Date/DateTime round-trip evidence (REQ-P2-008).

Everything is built, read and written through the PUBLIC ``dbfbridge``
Direct Write/Direct Read contract:

    original Date/DateTime -> shifted Date/DateTime + protected vault offset
    -> recovered original Date/DateTime

with adversarial calendar content (NULL, leap day, leap-year/month/year
boundaries, midnight and late-evening DateTime values) and byte-identical
source verification.
"""

from __future__ import annotations

import hashlib
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import dbfbridge
from dbfbridge import DirectRecord, write_table

from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    TemporalShiftDomain,
)
from dbf_anonymizer.vault.mappings import temporal_parameter
from support.memo_tables import field, schema as schema_of
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

TEMPORAL_FIELDS = (field("CODE", "C", 8), field("WHEN", "D", 8), field("MOMENT", "T", 8))

TEMPORAL_RECORDS: tuple[dict[str, object], ...] = (
    {"CODE": "T-NULL", "WHEN": None, "MOMENT": None},
    {"CODE": "T-LEAP", "WHEN": date(2020, 2, 29), "MOMENT": datetime(2020, 2, 29, 0, 0, 0)},
    {"CODE": "T-YEAR", "WHEN": date(2019, 12, 31), "MOMENT": datetime(2019, 12, 31, 23, 59, 58, 999000)},
    {"CODE": "T-MID", "WHEN": date(2024, 2, 29), "MOMENT": datetime(2024, 2, 29, 12, 34, 56)},
    {"CODE": "T-EOM", "WHEN": date(2020, 4, 30), "MOMENT": datetime(2020, 4, 30, 6, 30, 0)},
)


def _vault(tmp_path: Path, *, create: bool) -> VaultDatabase:
    if create:
        return VaultDatabase.open(
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            create=True,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
            dbfbridge_version="1.1.0",
        )
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def _hashes(dbf_path: Path) -> dict[str, str]:
    import hashlib

    hashes = {"dbf": hashlib.sha256(dbf_path.read_bytes()).hexdigest()}
    companion = dbf_path.with_suffix(".fpt")
    if companion.is_file():
        hashes["fpt"] = hashlib.sha256(companion.read_bytes()).hexdigest()
    return hashes


def _records(dbf_path: Path) -> list[DirectRecord]:
    return list(dbfbridge.iter_records(dbf_path, include_deleted=True))


def _write_destination(
    directory: Path, stem: str, schema_source: Path, records: list[DirectRecord]
) -> Path:
    destination = directory / stem
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_table(destination, schema=dbfbridge.read_schema(schema_source), records=records)
    return destination


def test_full_temporal_roundtrip_through_public_dbf_boundary(tmp_path: Path) -> None:
    """original -> shifted + protected vault offset -> recovered original."""
    source = tmp_path / "src" / "temporal.dbf"
    source.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        source,
        schema=schema_of(TEMPORAL_FIELDS),
        records=[
            DirectRecord(physical_index=index, deleted=False, values=dict(record))
            for index, record in enumerate(TEMPORAL_RECORDS)
        ],
    )
    hashes_before = _hashes(source)
    originals = _records(source)

    with _vault(tmp_path, create=True) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            for record in originals:
                domain.observe(record.values["WHEN"])
                domain.observe(record.values["MOMENT"])
            offset = domain.finalize()
            assert offset != 0
            shifted_records = [
                DirectRecord(
                    physical_index=record.physical_index,
                    deleted=record.deleted,
                    values={
                        "CODE": record.values["CODE"],
                        "WHEN": domain.shifted(record.values["WHEN"]),
                        "MOMENT": domain.shifted(record.values["MOMENT"]),
                    },
                )
                for record in originals
            ]

    shifted_path = _write_destination(tmp_path / "shifted", "temporal.dbf", source, shifted_records)
    shifted_read = _records(shifted_path)
    assert len(shifted_read) == len(originals)
    for original, shifted in zip(originals, shifted_read):
        assert shifted.values["CODE"] == original.values["CODE"]
        for name in ("WHEN", "MOMENT"):
            expected = domain.shifted(original.values[name])
            assert shifted.values[name] == expected
            if name == "WHEN" and expected is not None:
                assert shifted.values[name] != original.values[name]  # real shift
            if name == "MOMENT" and expected is not None and isinstance(expected, datetime):
                assert shifted.values[name].time() == expected.time()
                assert (shifted.values[name].hour, shifted.values[name].minute) == (
                    original.values[name].hour,  # type: ignore[union-attr]
                    original.values[name].minute,  # type: ignore[union-attr]
                )
    # Intervals preserved in the real artifact.
    pairs = ((1, 3), (2, 4))
    for i, j in pairs:
        for name in ("WHEN", "MOMENT"):
            a, b = originals[i].values[name], originals[j].values[name]
            if a is None or b is None:
                continue
            assert (shifted_read[j].values[name] - shifted_read[i].values[name]) == (b - a)
    # NULL stays NULL in the real artifact.
    assert shifted_read[0].values["WHEN"] is None and shifted_read[0].values["MOMENT"] is None

    # Recovery through the vault reconstructs the original logical values.
    recovered: list[DirectRecord] = []
    for record in shifted_read:
        recovered.append(
            DirectRecord(
                physical_index=record.physical_index,
                deleted=record.deleted,
                values={
                    "CODE": record.values["CODE"],
                    "WHEN": domain.recover(record.values["WHEN"]),
                    "MOMENT": domain.recover(record.values["MOMENT"]),
                },
            )
        )
    recovered_path = _write_destination(tmp_path / "recovered", "temporal.dbf", source, recovered)
    reread = _records(recovered_path)
    for original, back in zip(originals, reread):
        assert dict(back.values) == dict(original.values)
    # The source stayed byte-identical through the whole cycle.
    assert _hashes(source) == hashes_before


def test_temporal_boundary_domains_through_real_artifacts(tmp_path: Path) -> None:
    """date.min-only and date.max-only domains keep single-sided offsets."""
    from dbf_anonymizer import ErrorCode, MappingError

    extremes = (date(1, 1, 1), date(2, 1, 1))
    maximum = (date(9999, 12, 30), date(9999, 12, 31))
    fields = (field("CODE", "C", 8), field("WHEN", "D", 8))
    for stem, values in (("minside", extremes), ("maxside", maximum)):
        source = tmp_path / "src" / f"{stem}.dbf"
        source.parent.mkdir(parents=True, exist_ok=True)
        write_table(
            source,
            schema=schema_of(fields),
            records=[
                DirectRecord(
                    physical_index=index, deleted=False, values={"CODE": f"C{index}", "WHEN": value}
                )
                for index, value in enumerate(values)
            ],
        )
        hashes_before = _hashes(source)
        with _vault(tmp_path / f"vault-{stem}", create=True) as vault:
            with writer_session(vault):
                domain = TemporalShiftDomain(vault, domain_name=stem)
                for record in _records(source):
                    domain.observe(record.values["WHEN"])
                offset = domain.finalize()
                assert offset != 0
                shifted = [domain.shifted(r.values["WHEN"]) for r in _records(source)]
                for original_value, shifted_value in zip(values, shifted):
                    assert shifted_value != original_value  # real non-zero shift
        with _vault(tmp_path / f"vault-{stem}", create=False) as vault:
            domain = TemporalShiftDomain(vault, domain_name=stem)
            for original_value, shifted_value in zip(values, shifted):
                assert domain.recover(shifted_value) == original_value
        # The source stayed byte-identical through the whole cycle
        # (real comparison against the captured pre-repair state).
        assert _hashes(source) == hashes_before


def test_all_null_temporal_dbf_completes_the_real_flow(tmp_path: Path) -> None:
    """A real DBF whose every D/T cell is NULL is a valid EMPTY domain."""
    source = tmp_path / "src" / "allnull.dbf"
    source.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        source,
        schema=schema_of(TEMPORAL_FIELDS),
        records=[
            DirectRecord(
                physical_index=index, deleted=False, values=dict(record)
            )
            for index, record in enumerate(
                (
                    {"CODE": "N-1", "WHEN": None, "MOMENT": None},
                    {"CODE": "N-2", "WHEN": None, "MOMENT": None},
                    {"CODE": "N-3", "WHEN": None, "MOMENT": None},
                )
            )
        ],
    )
    hashes_before = _hashes(source)
    originals = _records(source)
    assert all(
        record.values["WHEN"] is None and record.values["MOMENT"] is None
        for record in originals
    )

    with _vault(tmp_path, create=True) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            for record in originals:
                domain.observe(record.values["WHEN"])
                domain.observe(record.values["MOMENT"])
            assert domain.finalize() is None  # EMPTY domain: no offset
            shifted_records = [
                DirectRecord(
                    physical_index=record.physical_index,
                    deleted=record.deleted,
                    values={
                        "CODE": record.values["CODE"],
                        "WHEN": domain.shifted(record.values["WHEN"]),
                        "MOMENT": domain.shifted(record.values["MOMENT"]),
                    },
                )
                for record in originals
            ]

    shifted_path = _write_destination(
        tmp_path / "shifted", "allnull.dbf", source, shifted_records
    )
    shifted_read = _records(shifted_path)
    for shifted in shifted_read:
        # Every output D/T remains NULL through the public contract.
        assert shifted.values["WHEN"] is None and shifted.values["MOMENT"] is None
    # Recovery of NULL is NULL without any temporal recovery value.
    with _vault(tmp_path, create=False) as vault:
        reopened_domain = TemporalShiftDomain(vault)
        assert reopened_domain.domain_id == domain.domain_id
        for shifted in shifted_read:
            assert reopened_domain.recover(shifted.values["WHEN"]) is None
            assert reopened_domain.recover(shifted.values["MOMENT"]) is None
        assert temporal_parameter(vault, domain.domain_id) is None
    # The source stayed byte-identical through the whole cycle.
    assert _hashes(source) == hashes_before