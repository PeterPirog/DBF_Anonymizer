"""Focused REQ-P7-003 contract for an actually installed wheel."""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import dbf_anonymizer
import dbf_anonymizer.recovery as recovery_module
from dbf_anonymizer import ErrorCode, RecoveryError, RecoveryPolicy, capabilities, recover
from dbf_anonymizer.cli import main as cli_main


def main() -> int:
    origin = Path(dbf_anonymizer.__file__).resolve()
    lowered_parts = {part.lower() for part in origin.parts}
    assert lowered_parts & {"site-packages", "dist-packages"}, origin

    assert capabilities(RecoveryPolicy.DISABLED).recovery is False

    with (
        patch.object(
            recovery_module,
            "_VerifyVault",
            side_effect=AssertionError("disabled recovery opened the vault"),
        ) as vault_constructor,
        patch.object(
            sqlite3,
            "connect",
            side_effect=AssertionError("disabled recovery connected to SQLite"),
        ) as sqlite_connect,
    ):
        try:
            recover(
                "missing-pseudonymized",
                vault="private-vault-canary.sqlite",
                output="must-not-exist",
                recovery_policy=RecoveryPolicy.DISABLED,
            )
        except RecoveryError as error:
            assert error.code is ErrorCode.RECOVERY_NOT_PERMITTED
        else:  # pragma: no cover - CI contract failure
            raise AssertionError("disabled recovery unexpectedly succeeded")
        vault_constructor.assert_not_called()
        sqlite_connect.assert_not_called()

    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(
            [
                "recover",
                "missing-pseudonymized",
                "private-vault-canary.sqlite",
                "must-not-exist",
                "--recovery-policy",
                "disabled",
                "--json",
            ]
        )
    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["code"] == ErrorCode.RECOVERY_NOT_PERMITTED.value
    assert "private-vault-canary" not in stdout.getvalue() + stderr.getvalue()

    print(f"REQ-P7-003 installed-wheel contract PASSED: {origin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
