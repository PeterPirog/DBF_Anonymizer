"""Advanced DBF/VFP field-semantics workflow (public API only).

Run:

    python examples/field_semantics_workflow.py [WORK_ROOT]

One deterministic synthetic table (``registry.dbf``) exercises the
privacy-critical VFP field facts end to end through the PUBLIC dbfbridge
writer/reader APIs and the public DBF_Anonymizer workflow:

- SHARED TEXT DOMAIN (cross-type) — the SAME non-empty logical value
  ``SYNTH-SHARED`` occurs in the Character field ``NAME`` AND the Varchar
  field ``VARVAL`` (compatible widths); after pseudonymization both fields
  MUST carry the same pseudonym (one GLOBAL_TEXT mapping domain spans all
  text fields of the dataset);
- DELETED RECORDS — the deleted record also carries the shared value: the
  deleted marker and the physical order stay truthful, the sensitive content
  (Character, Varchar and memo) is transformed like every active record, and
  the shared value maps to the SAME pseudonym as in the active records;
- DISTINCT ORIGINALS — a distinct non-empty Character original receives a
  DISTINCT pseudonym (bijectivity of the shared domain);
- NULL/EMPTY — NULL stays NULL and an empty Varchar stays empty (identities,
  never transformed values);
- MEMO/FPT — the memo companion is freshly written; memo content is masked
  type-preservingly and the ORIGINAL memo canaries cannot survive in the
  pseudonymized output (DBF or FPT) or in the DATA_ONLY bundle;
- VERIFICATION PASS and RECOVERY canonical_verified; the recovered copy
  restores the ORIGINAL values inside the trusted workspace only.

Evidence patterns used are the bounded synthetic-canary byte scans already
used by the repository's architecture acceptance tests.  No DBF/FPT bytes
are hand-parsed; no original value is printed; no vault row is read.
The optional ``WORK_ROOT`` argument must NOT exist yet (fail-closed).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import dbf_anonymizer as public
import dbfbridge

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution

_SHARED_ORIGINAL = "SYNTH-SHARED"
_MEMO_CANARIES = ("MEMO-CANARY-A", "MEMO-CANARY-B", "MEMO-CANARY-C")
_TEXT_CANARIES = ("SYNTH-SHARED", "SYNTH-DISTINCT")


def _require(condition: bool, message: str) -> None:
    """An explicit safety check that cannot disappear under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _bytes_with_canaries(root: Path) -> bytes:
    return b"".join(path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file())


def _records(dbf_path: Path) -> tuple[dbfbridge.DirectRecord, ...]:
    return tuple(dbfbridge.iter_records(dbf_path, include_deleted=True, memo="inline"))


def main() -> None:
    work_root = synthetic_dataset.workspace_from_arguments("field-semantics")

    source = synthetic_dataset.create_field_semantics_dataset(work_root / "source")
    source_before = _hash_tree(source)
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the plan; nothing was executed")
    result = public.pseudonymize(plan)

    # 1) Deleted records: physical order + deleted flags stay truthful.
    output_records = _records(output / "registry.dbf")
    _require(
        [(record.physical_index, record.deleted) for record in output_records]
        == [(0, False), (1, False), (2, True), (3, False)],
        "the deleted marker or the physical record order was not preserved",
    )

    by_id = {record.values["ID"]: record for record in output_records}

    # CROSS-TYPE SHARED DOMAIN: the same original logical value occurs in the
    # Character and the Varchar field (active AND deleted record) — all four
    # cells must carry ONE identical pseudonym, and no original may survive.
    shared_pseudonym = by_id[1].values["NAME"]
    _require(
        shared_pseudonym
        == by_id[1].values["VARVAL"]
        == by_id[3].values["NAME"]
        == by_id[3].values["VARVAL"],
        "equal Character/Varchar originals (active and deleted) must map to one shared pseudonym",
    )
    _require(
        shared_pseudonym not in (None, "", _SHARED_ORIGINAL),
        "the shared pseudonym must be a genuine transformed value",
    )

    # DISTINCT ORIGINALS stay distinct (bijectivity of the shared domain).
    _require(
        by_id[4].values["NAME"] not in (None, "", "SYNTH-DISTINCT", shared_pseudonym),
        "a distinct original must map to a distinct pseudonym",
    )

    # NULL and empty identities.
    _require(
        by_id[2].values["NAME"] is None and by_id[2].values["VARVAL"] is None,
        "NULL was not preserved",
    )
    _require(by_id[4].values["VARVAL"] == "", "an empty string was not preserved as empty")

    # 4) Memo content is masked type-preservingly — including the DELETED row.
    for identifier in (1, 2, 3, 4):
        note = by_id[identifier].values["NOTE"]
        _require(
            isinstance(note, str) and note not in _MEMO_CANARIES, "memo content was not masked"
        )

    # 5) No synthetic canary survives in the pseudonymized output (DBF+FPT)
    #    — the same bounded canary byte-scan evidence the architecture
    #    acceptance tests use.
    output_blob = _bytes_with_canaries(output)
    for canary in (*_TEXT_CANARIES, *_MEMO_CANARIES):
        _require(
            canary.encode("utf-8") not in output_blob,
            f"a synthetic canary survived in the pseudonymized output: {canary}",
        )

    # 6) The source stayed byte-identical (read-only by contract).
    _require(_hash_tree(source) == source_before, "the source dataset was modified")

    verification = public.verify_dataset(result, source=source, vault=vault)
    _require(
        verification.status is public.VerificationStatus.PASS,
        "dataset verification did not reach PASS",
    )

    # 7) Authorized recovery restores the originals INSIDE the trusted
    #    workspace (never printed, never transferred).
    recovered = public.recover(
        output,
        vault=vault,
        output=work_root / "recovered",
        recovery_policy=public.RecoveryPolicy.ENABLED,
    )
    _require(recovered.canonical_verified, "recovery did not verify the canonical dataset")
    recovered_records = _records(work_root / "recovered" / "registry.dbf")
    recovered_by_id = {record.values["ID"]: record for record in recovered_records}
    _require(
        recovered_by_id[1].values["NAME"] == _SHARED_ORIGINAL
        and recovered_by_id[1].values["VARVAL"] == _SHARED_ORIGINAL
        and recovered_by_id[2].values["NAME"] is None
        and recovered_by_id[1].values["NOTE"] == "MEMO-CANARY-A"
        and recovered_by_id[3].deleted,
        "recovery did not restore the original logical data faithfully",
    )

    # 8) The DATA_ONLY bundle excludes recovery material: no canary and no
    #    SQLite artifact inside it.
    bundle_path = work_root / "bundle"
    bundle = public.create_transfer_bundle(result, destination=bundle_path, profile="DATA_ONLY")
    _require(bundle.verified, "the bundle was not verified at creation")
    standalone = public.verify_transfer_bundle(bundle_path)
    _require(standalone.verified, "the bundle was not verified standalone")
    bundle_blob = _bytes_with_canaries(bundle_path)
    for canary in (*_TEXT_CANARIES, *_MEMO_CANARIES):
        _require(
            canary.encode("utf-8") not in bundle_blob,
            f"a synthetic canary survived in the DATA_ONLY bundle: {canary}",
        )
    _require(
        not tuple(bundle_path.rglob("*.sqlite3*")),
        "no SQLite database may appear inside a DATA_ONLY bundle",
    )

    print("DBF_Anonymizer field-semantics workflow (synthetic data)")
    print("C/V cross-type proof passed: equal Character+Varchar originals (active and deleted)")
    print("  -> one shared pseudonym; VARCHAR SHARES THE TEXT DOMAIN (proven above)")
    print("distinct originals stay distinct; NULL and empty values stay identities")
    print("deleted records: marker + physical order preserved, content transformed")
    print("memo/FPT: freshly written, masked, no canary in output DBF/FPT or bundle")
    print(f"verification status: {verification.status.value}")
    print("recovery: canonical_verified=True (originals restored in the trusted workspace only)")
    print(f"bundle verified standalone: {standalone.verified}")


if __name__ == "__main__":
    main()
