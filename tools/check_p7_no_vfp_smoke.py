"""Trusted hosted-runner no-VFP smoke (REQ-P7-006).

Proves, on a plain hosted runner with NO Visual FoxPro present, that the
INSTALLED package:

* imports WITHOUT loading any process-spawning, COM automation or VFP
  backend module (``subprocess``, ``ctypes``, ``comtypes``,
  ``win32com``/``pythoncom`` and the VFP vocabulary), so the production
  runtime structurally CANNOT discover, launch or talk to ``vfp9.exe``;
* exposes the public capabilities surface and completes the full synthetic
  standalone workflow (:func:`run_self_test`) end-to-end with no VFP and no
  VFP-specific code path.

The probe runs in a FRESH interpreter subprocess so the ``sys.modules``
snapshot is not polluted by the launcher itself.  The launcher (this tool)
is CI-side tooling and is never part of the installed runtime.

Usage:
    python tools/check_p7_no_vfp_smoke.py            # probe this interpreter
    python tools/check_p7_no_vfp_smoke.py --python <venv python path>
    python tools/check_p7_no_vfp_smoke.py --allow-editable-install  (local dev)

Exit code 0 prints the sanitized JSON evidence; any failure exits non-zero.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_PROBE_PREFIX = (
    "import os as _probe_os\n"
    "_ALLOW_EDITABLE = "
    "_probe_os.environ.get('DBF_NO_VFP_ALLOW_EDITABLE') == '1'\n"
)

_PROBE_BODY = r"""
import json
import sys

before = set(sys.modules)

import dbf_anonymizer
from dbf_anonymizer import RecoveryPolicy, capabilities

caps = capabilities(RecoveryPolicy.DISABLED)

from dbf_anonymizer.standalone_health import run_self_test

result = run_self_test()

banned = (
    "vfp",
    "win32com",
    "comtypes",
    "pythoncom",
    "subprocess",
    "ctypes",
    "multiprocessing",
)
leaked = sorted(
    name
    for name in set(sys.modules) - before
    if any(token in name.lower() for token in banned)
)
assert not leaked, f"forbidden modules loaded at import/runtime: {leaked}"
assert caps.direct_read is True
assert caps.recovery is False
verdict = result.to_dict()
assert verdict["preflight_ready"] is True
assert verdict["bundle_verified"] is True
assert verdict["canonical_match"] is True
origin = dbf_anonymizer.__file__
if not _ALLOW_EDITABLE:
    assert "site-packages" in origin.lower(), origin
print(
    json.dumps(
        {
            "result": "PASS",
            "import_origin": origin,
            "capabilities": caps.to_dict(),
            "self_test": verdict,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""

PROBE = _PROBE_PREFIX + _PROBE_BODY


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter to probe (defaults to the running interpreter)",
    )
    parser.add_argument(
        "--allow-editable-install",
        action="store_true",
        help="skip the site-packages origin assertion (local editable installs)",
    )
    arguments = parser.parse_args()
    environment = dict(os.environ)
    environment["DBF_NO_VFP_ALLOW_EDITABLE"] = "1" if arguments.allow_editable_install else "0"
    completed = subprocess.run(
        [arguments.python, "-c", PROBE],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        print("NO-VFP SMOKE FAILED", file=sys.stderr)
        return 1
    evidence = json.loads(completed.stdout)
    evidence["probed_interpreter"] = arguments.python
    print(json.dumps(evidence, sort_keys=True, indent=2))
    print("REQ-P7-006 no-VFP smoke PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
