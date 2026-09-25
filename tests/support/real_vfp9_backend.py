"""Explicit test-only backend for trusted local Visual FoxPro 9 acceptance.

The production package never imports this module.  The backend is loaded only
through the opt-in acceptance-test factory environment variable and launches
the exact executable path supplied by that trusted test environment.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

from dbf_anonymizer.index_backend import (
    IndexRebuildOutcome,
    IndexRebuildRequest,
    IndexVerificationOutcome,
    IndexVerificationRequest,
)
from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
)

_EXECUTABLE_ENV = "DBF_ANONYMIZER_REAL_VFP9_EXECUTABLE"
_BACKEND_ID = "trusted-local-vfp9-test-backend"
_FIXTURE_TABLE = "structural/indexed_table.dbf"
_FIXTURE_DBF_SHA256 = (
    "3076275e4bcd174500a9e1954596b5fd62f826e957fd9e3136b7bfe45e6054aa"
)
_FIXTURE_CDX_SHA256 = (
    "b5ab7ee37138971be4c565dcb2871879b700b416d8861ae2f5203a9e695a3fe7"
)


def _vfp_literal(value: Path) -> str:
    rendered = str(value)
    if "]" in rendered or "\r" in rendered or "\n" in rendered:
        raise RuntimeError("real VFP9 test path is not representable")
    return f"[{rendered}]"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RealVFP9TestBackend:
    """Narrow real-runtime adapter for the committed synthetic CDX fixture."""

    def __init__(self, executable: Path) -> None:
        self._executable = executable.resolve(strict=True)
        self.runtime_version = self._probe_version()
        self.expected_tag_inventory: tuple[str, ...] = ()
        self.actual_tag_inventory: tuple[str, ...] = ()
        self.actual_record_count: int | None = None
        self.table_opened = False
        self.published_table_opened = False
        self.staged_table_existed_before_rebuild = False
        self.staged_cdx_existed_before_rebuild = False
        self.source_cdx_hash_at_rebuild: str | None = None
        self.rebuilt_cdx_hash: str | None = None
        self.last_failure_evidence: tuple[str, ...] = ()

    def capabilities(self) -> IndexBackendCapability:
        return IndexBackendCapability(
            backend_id=_BACKEND_ID,
            backend_schema_version="1.0",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            supports_structural_cdx_rebuild=True,
            supports_standalone_idx_rebuild=False,
            supports_verification=True,
            vfp_runtime_available=True,
        )

    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        self._validate_request(request)
        staged_cdx = request.staged_table_path.with_suffix(".cdx")
        source_cdx = request.source_table_path.with_suffix(".cdx")
        self.staged_table_existed_before_rebuild = request.staged_table_path.is_file()
        self.staged_cdx_existed_before_rebuild = staged_cdx.exists()
        self.source_cdx_hash_at_rebuild = _digest(source_cdx)
        if not self.staged_table_existed_before_rebuild:
            raise RuntimeError("fresh staged DBF is missing")
        if self.staged_cdx_existed_before_rebuild:
            raise RuntimeError("staged CDX existed before authoritative rebuild")

        lines = self._run_program(
            f"""
SET TALK OFF
SET SAFETY OFF
SET NOTIFY OFF
SET EXCLUSIVE OFF
SET CPDIALOG OFF
CLOSE ALL
LOCAL lcSource, lcStaged, lcStagedCdx, lcResult, lcStage, lnTags, lnIndex
LOCAL lcCommand, lcPayload, lnRecords
lcSource = {_vfp_literal(request.source_table_path)}
lcStaged = {_vfp_literal(request.staged_table_path)}
lcStagedCdx = {_vfp_literal(staged_cdx)}
lcResult = RESULT_PATH_TOKEN
lcStage = "SOURCE_OPEN"
ON ERROR DO vfp_failure WITH m.lcResult, m.lcStage
USE (m.lcSource) IN 0 ALIAS _source NOUPDATE SHARED
SELECT _source
lcStage = "SOURCE_TAGS"
lnTags = TAGCOUNT()
IF m.lnTags < 1
    ERROR 11
ENDIF
DIMENSION laTags[m.lnTags], laExpressions[m.lnTags]
FOR lnIndex = 1 TO m.lnTags
    laTags[m.lnIndex] = TAG(m.lnIndex)
    laExpressions[m.lnIndex] = SYS(14, m.lnIndex)
NEXT
USE IN _source
lcStage = "STAGED_PRECONDITION"
IF FILE(m.lcStagedCdx)
    ERROR 11
ENDIF
lcStage = "STAGED_OPEN"
USE (m.lcStaged) IN 0 ALIAS _staged EXCLUSIVE
SELECT _staged
lcStage = "STAGED_INDEX"
FOR lnIndex = 1 TO m.lnTags
    lcCommand = "INDEX ON " + laExpressions[m.lnIndex] + " TAG " + laTags[m.lnIndex]
    &lcCommand
NEXT
lnRecords = RECCOUNT()
USE IN _staged
lcPayload = "OK" + CHR(9) + VERSION() + CHR(13) + CHR(10)
lcPayload = m.lcPayload + "COUNT" + CHR(9) + TRANSFORM(m.lnRecords) + CHR(13) + CHR(10)
FOR lnIndex = 1 TO m.lnTags
    lcPayload = m.lcPayload + "TAG" + CHR(9) + laTags[m.lnIndex] + CHR(13) + CHR(10)
NEXT
STRTOFILE(m.lcPayload, m.lcResult, 0)
QUIT

PROCEDURE vfp_failure
LPARAMETERS tcResult, tcStage
LOCAL lcFailure
lcFailure = "FAILED" + CHR(9) + m.tcStage + CHR(9) + TRANSFORM(ERROR()) + CHR(9) + TRANSFORM(LINENO()) + CHR(13) + CHR(10)
ON ERROR
CLOSE ALL
STRTOFILE(m.lcFailure, m.tcResult, 0)
QUIT
ENDPROC
"""
        )
        _, tags = self._parse_evidence(lines)
        self.expected_tag_inventory = tags
        if not staged_cdx.is_file():
            raise RuntimeError("real VFP9 did not create a structural CDX")
        self.rebuilt_cdx_hash = _digest(staged_cdx)
        return IndexRebuildOutcome(
            result=IndexBackendResult(
                backend_id=_BACKEND_ID,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status="REBUILT",
                detail_code="REBUILT_OK",
            ),
            expected_tag_inventory=tags,
        )

    def verify_index(
        self, request: IndexVerificationRequest
    ) -> IndexVerificationOutcome:
        self._validate_staged_request(request)
        record_count, tags = self._inspect_table(request.staged_table_path)
        self.table_opened = True
        self.actual_record_count = record_count
        self.actual_tag_inventory = tags
        status = "VERIFIED" if tags == self.expected_tag_inventory else "MISMATCH"
        detail_code = (
            "VERIFIED_OK" if status == "VERIFIED" else "TAG_INVENTORY_MISMATCH"
        )
        return IndexVerificationOutcome(
            result=IndexVerificationResult(
                backend_id=_BACKEND_ID,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status=status,
                detail_code=detail_code,
            ),
            table_opened=True,
            actual_record_count=record_count,
            actual_tag_inventory=tags,
        )

    def inspect_published_table(
        self, table_path: Path
    ) -> tuple[int, tuple[str, ...]]:
        """Reopen one published synthetic fixture through real VFP9."""
        if table_path.name.lower() != "indexed_table.dbf":
            raise RuntimeError("real VFP9 test backend accepts the synthetic fixture only")
        record_count, tags = self._inspect_table(table_path)
        self.published_table_opened = True
        return record_count, tags

    def _inspect_table(self, table_path: Path) -> tuple[int, tuple[str, ...]]:
        lines = self._run_program(
            f"""
SET TALK OFF
SET SAFETY OFF
SET NOTIFY OFF
SET EXCLUSIVE OFF
SET CPDIALOG OFF
CLOSE ALL
LOCAL lcStaged, lcResult, lcPayload, lnRecords, lnTags, lnIndex
lcStaged = {_vfp_literal(table_path)}
lcResult = RESULT_PATH_TOKEN
ON ERROR DO vfp_failure WITH m.lcResult
USE (m.lcStaged) IN 0 ALIAS _verified NOUPDATE SHARED
SELECT _verified
lnRecords = RECCOUNT()
lnTags = TAGCOUNT()
lcPayload = "OK" + CHR(9) + VERSION() + CHR(13) + CHR(10)
lcPayload = m.lcPayload + "COUNT" + CHR(9) + TRANSFORM(m.lnRecords) + CHR(13) + CHR(10)
FOR lnIndex = 1 TO m.lnTags
    lcPayload = m.lcPayload + "TAG" + CHR(9) + TAG(m.lnIndex) + CHR(13) + CHR(10)
NEXT
USE IN _verified
STRTOFILE(m.lcPayload, m.lcResult, 0)
QUIT

PROCEDURE vfp_failure
LPARAMETERS tcResult
ON ERROR
CLOSE ALL
STRTOFILE("FAILED" + CHR(13) + CHR(10), m.tcResult, 0)
QUIT
ENDPROC
"""
        )
        return self._parse_evidence(lines)

    def _probe_version(self) -> str:
        lines = self._run_program(
            """
SET TALK OFF
SET SAFETY OFF
SET NOTIFY OFF
LOCAL lcResult
lcResult = RESULT_PATH_TOKEN
STRTOFILE("OK" + CHR(9) + VERSION() + CHR(13) + CHR(10), m.lcResult, 0)
QUIT
"""
        )
        first = lines[0].split("\t", 1)
        if len(first) != 2 or first[0] != "OK" or not first[1]:
            raise RuntimeError("real VFP9 version probe returned invalid evidence")
        return first[1]

    def _run_program(self, source: str) -> tuple[str, ...]:
        with tempfile.TemporaryDirectory(prefix="dbf-anonymizer-vfp9-") as raw:
            work = Path(raw)
            program = work / "acceptance.prg"
            result = work / "evidence.txt"
            program.write_text(
                source.replace("RESULT_PATH_TOKEN", _vfp_literal(result)).lstrip(),
                encoding="ascii",
            )
            completed = subprocess.run(
                (str(self._executable), "-t", str(program)),
                cwd=self._executable.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=60,
            )
            if completed.returncode != 0 or not result.is_file():
                raise RuntimeError("real VFP9 test command failed")
            lines = tuple(
                line.rstrip("\r")
                for line in result.read_text(encoding="ascii").splitlines()
                if line
            )
            if not lines or lines[0].startswith("FAILED"):
                self.last_failure_evidence = lines
                raise RuntimeError("real VFP9 test program refused the operation")
            return lines

    @staticmethod
    def _parse_evidence(lines: tuple[str, ...]) -> tuple[int, tuple[str, ...]]:
        if not lines or not lines[0].startswith("OK\t"):
            raise RuntimeError("real VFP9 evidence is malformed")
        counts = [
            line.split("\t", 1)[1] for line in lines if line.startswith("COUNT\t")
        ]
        tags = tuple(
            line.split("\t", 1)[1].upper()
            for line in lines
            if line.startswith("TAG\t")
        )
        if len(counts) != 1 or not tags:
            raise RuntimeError("real VFP9 evidence is incomplete")
        return int(counts[0]), tags

    @staticmethod
    def _validate_request(request: IndexRebuildRequest) -> None:
        if request.artifact_class != "STRUCTURAL_CDX":
            raise RuntimeError("real VFP9 test backend supports structural CDX only")
        if request.table_path != _FIXTURE_TABLE:
            raise RuntimeError("real VFP9 test backend accepts the synthetic fixture only")
        if not any(part.endswith(".staging") for part in request.staged_table_path.parts):
            raise RuntimeError("real VFP9 test backend requires protected staging")
        source_cdx = request.source_table_path.with_suffix(".cdx")
        if not source_cdx.is_file():
            raise RuntimeError("synthetic source structural CDX is missing")
        if (
            _digest(request.source_table_path) != _FIXTURE_DBF_SHA256
            or _digest(source_cdx) != _FIXTURE_CDX_SHA256
        ):
            raise RuntimeError("real VFP9 test backend accepts the committed fixture only")

    @staticmethod
    def _validate_staged_request(request: IndexVerificationRequest) -> None:
        if request.artifact_class != "STRUCTURAL_CDX":
            raise RuntimeError("real VFP9 test backend supports structural CDX only")
        if request.table_path != _FIXTURE_TABLE:
            raise RuntimeError("real VFP9 test backend accepts the synthetic fixture only")
        if not any(part.endswith(".staging") for part in request.staged_table_path.parts):
            raise RuntimeError("real VFP9 test backend requires protected staging")


def create_backend() -> RealVFP9TestBackend:
    """Create the backend only for an explicitly configured trusted test."""
    raw_executable = os.environ.get(_EXECUTABLE_ENV)
    if not raw_executable:
        raise RuntimeError(f"{_EXECUTABLE_ENV} is required")
    executable = Path(raw_executable)
    if executable.name.lower() != "vfp9.exe":
        raise RuntimeError("real VFP9 test executable must be vfp9.exe")
    return RealVFP9TestBackend(executable)
