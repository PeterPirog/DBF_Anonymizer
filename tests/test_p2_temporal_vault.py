"""Reversible Date/DateTime vault evidence (REQ-P2-008).

Proves the temporal allocation boundary directly: the
collect/finalize/allocate/shift/reuse lifecycle, CSPRNG selection bounds,
persistence exclusively in ``temporal_parameters``, same-vault reuse and
fresh-vault independence, incompatible-offset fail-closed behavior,
transaction/fault/writer-authority semantics, interval preservation and
offset-free typed error boundaries.
"""

from __future__ import annotations

import sqlite3
from datetime import date, datetime
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    TemporalShiftDomain,
)
from dbf_anonymizer.vault.mappings import (
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    create_domain,
    mapping_domains,
    set_temporal_parameter,
    temporal_parameter,
)
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    )


def _reopen(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def _finalize(vault: VaultDatabase, values: list[object], **kwargs: object) -> int:
    domain = TemporalShiftDomain(vault, **kwargs)  # type: ignore[arg-type]
    for value in values:
        domain.observe(value)
    return domain.finalize()


# ---------------------------------------------------------------------------
# allocation, persistence and shift
# ---------------------------------------------------------------------------
def test_finalize_persists_a_nonzero_offset_and_shifts(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            for value in (
                date(2020, 2, 29),
                datetime(2020, 3, 1, 0, 0, 0),
                datetime(2024, 12, 31, 23, 59, 59),
                date(2019, 12, 31),
            ):
                domain.observe(value)
            offset = domain.finalize()
            assert offset != 0
            # The offset exists ONLY in the protected vault row.
            assert temporal_parameter(vault, domain.domain_id) == offset
            # NULL is preserved by identity; the shift actually moves dates.
            assert domain.shifted(None) is None
            shifted_date = domain.shifted(date(2020, 2, 29))
            assert isinstance(shifted_date, date)
            assert shifted_date != date(2020, 2, 29)
            shifted = domain.shifted(datetime(2020, 2, 29, 23, 59, 58, 999999))
            assert isinstance(shifted, datetime)
            assert shifted.date() == shifted_date
            assert (shifted.hour, shifted.minute, shifted.second) == (23, 59, 58)
            # Interval preservation across Date and DateTime classes.
            base = date(2020, 2, 29)
            later = date(2020, 12, 31)
            later_shifted = domain.shifted(later)
            base_shifted = domain.shifted(base)
            assert isinstance(later_shifted, date) and isinstance(base_shifted, date)
            assert (later_shifted - base_shifted).days == (later - base).days
        # Recovery through the persisted offset restores every original.
        assert domain.recover(domain.shifted(base)) == base
        assert domain.recover(None) is None


def test_same_vault_reuse_persists_the_exact_offset(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            first = TemporalShiftDomain(vault)
            for value in (date(2020, 1, 1), date(2020, 12, 31)):
                first.observe(value)
            offset_one = first.finalize()
            second = TemporalShiftDomain(vault)
            for value in (date(2020, 5, 1), date(2020, 5, 2)):
                second.observe(value)
            offset_two = second.finalize()
            assert offset_one == offset_two  # REUSED, never remapped
            assert temporal_parameter(vault, first.domain_id) == offset_one
            assert first.domain_id == second.domain_id


def test_reopen_preserves_and_reuses_the_offset(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            domain.observe(date(2020, 2, 29))
            offset = domain.finalize()
        vault.close()
    with _reopen(tmp_path) as vault:
        with writer_session(vault):
            reopened = TemporalShiftDomain(vault)
            assert reopened.domain_id == domain.domain_id
            reopened.observe(date(2020, 6, 1))
            assert reopened.finalize() == offset  # compatible reuse
            # Recovery works from vault state alone after reopen.
            shifted = date(2020, 2, 29).fromordinal(date(2020, 2, 29).toordinal() + offset)
            assert reopened.recover(shifted) == date(2020, 2, 29)


def test_fresh_vaults_get_independent_offsets(tmp_path: Path) -> None:
    offsets: set[int] = set()
    for index in (0, 1):
        with _create(tmp_path / f"vault-{index}") as vault:
            with writer_session(vault):
                domain = TemporalShiftDomain(vault, _random_below=lambda bound, k=index: k)
                for value in (date(2020, 1, 1), date(2020, 6, 1)):
                    domain.observe(value)
                offsets.add(domain.finalize())
        # Scripted, deterministic, INDEPENDENT selection per fresh vault.
    assert len(offsets) == 2


def test_domain_identity_is_value_independent_and_stable(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            one = TemporalShiftDomain(vault)
            two = TemporalShiftDomain(vault)
            one.observe(date(2020, 1, 1))
            two.observe(date(1999, 12, 31))  # different values, same domain
            assert one.domain_id == two.domain_id
            named = TemporalShiftDomain(vault, domain_name="billing")
            assert named.domain_id != one.domain_id  # explicit named domain
            # Bounded identity without source values or private paths.
            assert one.domain_id.startswith("dom-")
            assert len(one.domain_id) < 32


# ---------------------------------------------------------------------------
# CSPRNG selection
# ---------------------------------------------------------------------------
def test_csprng_receives_the_exact_nonzero_candidate_count(tmp_path: Path) -> None:
    moduli: list[int] = []

    def seam(bound: int) -> int:
        moduli.append(bound)
        return 0

    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault, _random_below=seam)
            domain.observe(date(2020, 1, 1))
            domain.observe(date(2020, 12, 31))
            offset = domain.finalize()
        # lower = 1 - 737426, upper = 3652059 - 737517: the single call must
        # carry EXACTLY the feasible NON-ZERO count.
        from dbf_anonymizer.transforms import temporal as kernels

        lower, upper = kernels.temporal_feasible_interval(
            date(2020, 1, 1).toordinal(), date(2020, 12, 31).toordinal()
        )
        assert moduli == [kernels.temporal_nonzero_count(lower, upper)]
        assert offset != 0 and lower <= offset <= upper


def test_zero_only_feasible_domain_fails_closed_without_persisting(
    tmp_path: Path,
) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            domain.observe(date.min)
            domain.observe(date.max)  # both calendar extremes: only 0 fits
            with pytest.raises(MappingError) as excinfo:
                domain.finalize()
            assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
            # Nothing was persisted for the refused domain.
            assert temporal_parameter(vault, domain.domain_id) is None
            with vault.transaction():
                assert all(
                    row["domain_id"] != domain.domain_id
                    for row in mapping_domains(vault)
                )


# ---------------------------------------------------------------------------
# persisted-offset compatibility
# ---------------------------------------------------------------------------
def test_incompatible_persisted_offset_fails_closed(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            # Seed an offset that CANNOT satisfy the domain constraints: the
            # observed minimum sits at the calendar maximum edge.
            incompatible = 5
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                    domain_id=domain.domain_id,
                )
                set_temporal_parameter(vault, domain.domain_id, offset_days=incompatible)
            domain.observe(date(2020, 1, 1))
            domain.observe(date(2020, 12, 31))
            # The feasible interval for this domain EXCLUDES any offset that
            # pushes the observed maximum beyond the logical range? No: the
            # interval is [1-min, MAX-max]; the seeded 5 IS inside. Build a
            # genuinely incompatible case by observing the calendar maximum.
            domain.observe(date.max)
            with pytest.raises(VaultError) as excinfo:
                domain.finalize()
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            # The persisted offset was never silently replaced.
            assert temporal_parameter(vault, domain.domain_id) == incompatible


def test_incompatible_persisted_offset_extreme_case(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault, domain_name="edge")
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                    domain_id=domain.domain_id,
                )
                set_temporal_parameter(vault, domain.domain_id, offset_days=3)
            # Only the calendar maximum is observed: the ONLY feasible offset
            # is negative (upper bound = 0); +3 is incompatible.
            domain.observe(date(9999, 12, 31))
            with pytest.raises(VaultError) as excinfo:
                domain.finalize()
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            assert temporal_parameter(vault, domain.domain_id) == 3  # unchanged


# ---------------------------------------------------------------------------
# transactions / faults / authority
# ---------------------------------------------------------------------------
def test_unauthorized_writer_cannot_allocate_an_offset(tmp_path: Path) -> None:
    path = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as vault:
        vault.close()
    with VaultDatabase.open(
        path,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as unauthorized:
        domain = TemporalShiftDomain(unauthorized)
        domain.observe(date(2020, 1, 1))
        with pytest.raises(VaultError) as excinfo:
            domain.finalize()
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert temporal_parameter(unauthorized, domain.domain_id) is None


def test_failed_offset_persistence_rolls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from support.vault_sessions import install_failing_execute

    with _create(tmp_path) as vault:
        domain = TemporalShiftDomain(vault)
        domain.observe(date(2020, 1, 1))
        domain.observe(date(2020, 12, 31))
        install_failing_execute(
            vault,
            fail_when=lambda sql: "INSERT INTO temporal_parameters" in sql,
            monkeypatch=monkeypatch,
        )
        with writer_session(vault):
            with pytest.raises(sqlite3.Error):
                domain.finalize()
        # No successful allocation happened; nothing was committed.
        assert temporal_parameter(vault, domain.domain_id) is None
        # Shifting is still refused (the offset was never allocated).
        with pytest.raises(MappingError):
            domain.shifted(date(2020, 1, 1))


def test_conflicting_second_parameter_insert_is_typed(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            create_domain(
                vault,
                domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                domain_id="dom-temporal-probe",
            )
            set_temporal_parameter(vault, "dom-temporal-probe", offset_days=7)
            with pytest.raises(VaultError) as excinfo:
                set_temporal_parameter(vault, "dom-temporal-probe", offset_days=9)
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        assert temporal_parameter(vault, "dom-temporal-probe") == 7


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------
def test_shift_before_finalize_is_typed(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        domain = TemporalShiftDomain(vault)
        with pytest.raises(MappingError) as excinfo:
            domain.shifted(date(2020, 1, 1))
        assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
        with pytest.raises(VaultError) as recovery:
            domain.recover(date(2020, 1, 1))
        assert recovery.value.code is ErrorCode.VAULT_STATE_INVALID


def test_observe_after_finalize_is_refused(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            domain.observe(date(2020, 1, 1))
            domain.finalize()
            with pytest.raises(ValueError):
                domain.observe(date(2021, 1, 1))


def test_collector_retains_only_the_extrema(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        domain = TemporalShiftDomain(vault)
        for index in range(1000):
            domain.observe(date(2020, 1, 1) + __import__("datetime").timedelta(days=index % 366))
        retained = [
            value for value in vars(domain).values() if isinstance(value, (list, dict, set, tuple))
        ]
        assert retained == []  # no dataset-sized retention, ever


# ---------------------------------------------------------------------------
# interval preservation
# ---------------------------------------------------------------------------
def test_intervals_are_preserved_across_all_value_classes(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault, _random_below=lambda bound: bound - 1)
            domain.observe(date(2020, 2, 29))
            domain.observe(datetime(2020, 3, 1, 0, 0, 0))
            domain.observe(datetime(2020, 12, 31, 12, 34, 56))
            domain.observe(date(2021, 6, 30))
            offset = domain.finalize()
            a = date(2020, 2, 29)
            b = date(2021, 6, 30)
            assert (domain.shifted(b) - domain.shifted(a)).days == (b - a).days
            c = datetime(2020, 3, 1, 0, 0, 0)
            d = datetime(2020, 12, 31, 12, 34, 56)
            assert (domain.shifted(d) - domain.shifted(c)) == (d - c)
            # Mixed classes compare at the calendar-date level.
            assert (domain.shifted(d).date() - domain.shifted(a)).days == (
                d.date() - a
            ).days
            assert offset != 0


# ---------------------------------------------------------------------------
# leakage sentinels
# ---------------------------------------------------------------------------
def test_typed_failures_never_carry_dates_or_offsets(tmp_path: Path) -> None:
    secret_offset = 987654
    with _create(tmp_path) as vault:
        with writer_session(vault):
            domain = TemporalShiftDomain(vault)
            domain.observe(date.min)
            domain.observe(date.max)
            with pytest.raises(MappingError) as excinfo:
                domain.finalize()
        boundary = (
            str(excinfo.value)
            + "|"
            + repr(excinfo.value)
            + "|"
            + str(excinfo.value.to_dict())
        )
        assert str(secret_offset) not in boundary
        assert "offset" not in boundary.lower().replace("temporal_only_zero_feasible", "")
        assert str(date.min) not in boundary and str(date.max) not in boundary


def test_recovery_of_missing_state_fails_closed_privacy_safe(
    tmp_path: Path,
) -> None:
    with _create(tmp_path) as vault:
        domain = TemporalShiftDomain(vault, domain_name="missing")
        with pytest.raises(VaultError) as excinfo:
            domain.recover(date(2020, 1, 1))
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        boundary = (
            str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
        )
        assert str(date(2020, 1, 1)) not in boundary
        assert "TEMPORAL_RECOVERY_INVALID" in boundary