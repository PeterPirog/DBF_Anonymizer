"""REQ-P1-007 — isolated import/capability purity evidence.

Public package import and capability discovery must create no files, open no
DBF, start no subprocess, instantiate no COM object, contact no network
endpoint and import no optional VFP backend. The acceptance evidence is a set
of isolated smoke tests: a fresh, ``-I``-isolated Python child process
installs filesystem/DBF/network/subprocess/COM sentinels BEFORE importing
``dbf_anonymizer`` and then either imports the package or calls
``capabilities()``.

The COM/optional-VFP evidence is a *real runtime import-attempt sentinel*: a
``sys.meta_path`` finder installed at the FRONT of the child's import
machinery fails fast on any attempt to *resolve or import* a forbidden root
(``win32com``, ``pythoncom``, ``comtypes``, ``pywintypes`` and the
architecture's external VFP toolchain provider) — including dynamic
``importlib.import_module``/``__import__`` attempts that an optional-import
fallback could hide while leaving ``sys.modules`` clean.  It raises
``SentinelViolation``, never ``ImportError``, so the forbidden attempt cannot
be swallowed as harmless absence; the recorded violations list stays
authoritative even if the code under test catches a broad exception.  On
Windows the child additionally replaces the direct COM/OLE activation entry
points (``ctypes.oledll``/``ctypes.windll`` loader access and
``ctypes.OleDLL``/``ctypes.WinDLL`` instantiation) with fail-fast sentinels
before the code under test runs, so no COM object can be instantiated; on
other platforms nothing is replaced and they keep running normally.

Negative-control scenarios prove the sentinels themselves fire: the child
deliberately attempts a forbidden dynamic import and an ordinary COM/OLE
activation route, and the negative-control test passes only because the
sentinel intercepts the action.  Post-operation ``sys.modules`` observation
remains as secondary evidence.

The pytest harness itself spawns the child interpreter (an allowed harness
action); the code under test inside the child must not spawn any process,
which the child's own subprocess sentinels prove.

The child also proves the capability-discovery contract: the public
``dbfbridge`` data operations (``inspect_table``, ``read_schema``,
``iter_records``, ``iter_raw_records``, ``write_table``) are replaced with
call sentinels before discovery, so any attempt to *execute* them (not merely
to inspect their callability) fails the test.

Result-contract evidence (deterministic JSON-safe ``to_dict()``, no absolute
paths, no original/source values, no secret/recovery data, truthful
``False`` future capabilities) is proven both in the isolated child and in
the ordinary pytest process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import dbf_anonymizer
from dbf_anonymizer import Capabilities

VERDICT_PREFIX = "DBF_PURITY_VERDICT:"

#: Optional backend and server modules that must never be *resolved or loaded*
#: by import/discovery.  The COM/ole set, the architecture's external VFP
#: toolchain provider and MCP/server frameworks stay outside this synchronous
#: transport-neutral package (REQ-P6-006/REQ-P7-001).
FORBIDDEN_BACKEND_MODULES = (
    "win32com,pythoncom,comtypes,pywintypes,mcp,fastmcp,fastapi,flask,"
    "starlette,aiohttp,mcp_vfp9sp2_toolchain,vfp_toolchain"
)

#: The five public dbfbridge data operations that discovery must never call.
DBFBRIDGE_DATA_OPERATIONS = (
    "inspect_table",
    "read_schema",
    "iter_records",
    "iter_raw_records",
    "write_table",
)

_EXPECTED_CAPABILITY_KEYS = {
    "schema_version",
    "model_type",
    "direct_read",
    "direct_write",
    "recovery",
    "transfer_bundle",
    "vfp_index_backend",
    "dbfbridge_version",
}

# The child is a self-contained script executed with ``-I`` (isolated mode).
# It installs every sentinel BEFORE importing dbf_anonymizer, then performs
# exactly one scenario: a bare package import, a capability discovery call or
# one of the sentinel negative-control probes.
CHILD_SCRIPT = r'''
import builtins
import ctypes
import importlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys

sys.dont_write_bytecode = True

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "import"
FORBIDDEN_MODULES = {
    name
    for name in os.environ.get("DBF_PURITY_FORBIDDEN_MODULES", "").split(",")
    if name
}

violations = []


class SentinelViolation(AssertionError):
    """A purity sentinel fired; the isolated run must fail."""


def _fail(kind, detail):
    message = "%s: %s" % (kind, detail)
    violations.append(message)
    raise SentinelViolation(message)


# --- filesystem sentinels (write-capable opens and mutations) ---------------
_DBF_SUFFIXES = (".dbf", ".fpt", ".cdx", ".idx", ".dbc", ".dct", ".dcx")
_WRITE_MODE_CHARS = frozenset("wax+")


def _path_text(file):
    if isinstance(file, bytes):
        return file.decode("utf-8", "replace")
    if isinstance(file, str):
        return file
    try:
        return os.fspath(file)
    except (TypeError, ValueError):
        return ""


def _reject_dbf_artifact(text):
    lowered = text.lower()
    for suffix in _DBF_SUFFIXES:
        if lowered.endswith(suffix):
            _fail("dbf-artifact-open", text)


_REAL_OPEN = builtins.open


def _guarded_open(file, mode="r", *args, **kwargs):
    text = _path_text(file)
    _reject_dbf_artifact(text)
    if text and set(mode) & _WRITE_MODE_CHARS:
        _fail("write-open", "path=%r mode=%r" % (text, mode))
    return _REAL_OPEN(file, mode, *args, **kwargs)


builtins.open = _guarded_open
io.open = _guarded_open

_REAL_OS_OPEN = os.open


def _guarded_os_open(path, flags, *args, **kwargs):
    text = _path_text(path)
    _reject_dbf_artifact(text)
    write_flags = (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_EXCL
    )
    if text and flags & write_flags:
        _fail("os-open-write", "path=%r flags=%#x" % (text, flags))
    return _REAL_OS_OPEN(path, flags, *args, **kwargs)


os.open = _guarded_os_open


def _blocked(name, kind):
    def _guard(*args, **kwargs):
        _fail(kind, name)

    return _guard


for mutation in (
    "mkdir",
    "makedirs",
    "remove",
    "unlink",
    "rmdir",
    "rename",
    "replace",
    "truncate",
):
    if hasattr(os, mutation):
        setattr(os, mutation, _blocked(mutation, "fs-mutation"))

# --- sqlite sentinel: creating any database file is a violation -------------
sqlite3.connect = _blocked("sqlite3.connect", "sqlite-open")

# --- network sentinels ------------------------------------------------------
def _blocked_socket_connect(*args, **kwargs):
    _fail("socket-connect", repr(args))


socket.socket.connect = _blocked_socket_connect
socket.socket.connect_ex = _blocked_socket_connect

for network_function in (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
):
    if hasattr(socket, network_function):
        setattr(socket, network_function, _blocked(network_function, "network"))

# --- subprocess sentinels ---------------------------------------------------
for process_function in (
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
):
    if hasattr(subprocess, process_function):
        setattr(subprocess, process_function, _blocked(process_function, "subprocess"))

for os_process_function in ("system", "popen"):
    if hasattr(os, os_process_function):
        setattr(os, os_process_function, _blocked(os_process_function, "os-process"))

for os_name in dir(os):
    if os_name.startswith(("spawn", "posix_spawn", "exec", "fork")):
        setattr(os, os_name, _blocked("os." + os_name, "os-process"))

for low_level_name in ("_winapi", "_posixsubprocess"):
    try:
        low_level = __import__(low_level_name)
    except ImportError:
        continue
    for attribute in dir(low_level):
        if (
            "CreateProcess" in attribute
            or attribute.startswith("fork_exec")
            or attribute.startswith("spawn")
        ):
            setattr(low_level, attribute, _blocked(low_level_name + "." + attribute,
                                                   "subprocess"))


# --- forbidden-import sentinel ----------------------------------------------
# A real runtime import-attempt sentinel: a meta-path finder at the FRONT of
# sys.meta_path, installed BEFORE the code under test runs.  Any attempt to
# resolve/import a forbidden root (ordinary ``import``, ``__import__``,
# ``importlib.import_module`` or ``importlib.util.find_spec``) records a
# privacy-safe violation and raises SentinelViolation -- NOT ImportError, so
# optional-import fallbacks cannot swallow it as harmless absence.  The
# violations list stays authoritative even if the code under test catches a
# broad exception.
class _ForbiddenImportFinder:
    def __init__(self, forbidden_roots):
        self._forbidden_roots = frozenset(forbidden_roots)

    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if root in self._forbidden_roots:
            _fail("forbidden-import", root)
        return None


sys.meta_path.insert(0, _ForbiddenImportFinder(FORBIDDEN_MODULES))

# --- COM/OLE activation sentinel (Windows; harmless no-op elsewhere) ---------
class _BlockedComLoader:
    """Fail-fast sentinel object replacing a COM/OLE activation entry point.

    Any attribute access, item access or call records a ``com-activation``
    violation and raises SentinelViolation BEFORE any real library load or
    COM object instantiation can happen.
    """

    def __init__(self, label):
        self.__dict__["_label"] = label

    def __getattr__(self, name):
        _fail("com-activation", "%s.%s" % (self.__dict__["_label"], name))

    def __getitem__(self, key):
        _fail("com-activation", "%s[%r]" % (self.__dict__["_label"], key))

    def __call__(self, *args, **kwargs):
        _fail("com-activation", self.__dict__["_label"])


def _install_com_activation_sentinel():
    """Replace the available Windows COM/OLE activation entry points.

    ``ctypes.oledll``/``ctypes.windll`` loader access and
    ``ctypes.OleDLL``/``ctypes.WinDLL`` instantiation are the common direct
    COM-loading/activation paths on Windows.  Those entry points exist only
    on Windows; on other platforms nothing is replaced and the platform keeps
    running normally (no Windows-only library is required, and the product
    package must not import ``ctypes`` merely to satisfy this test).
    """
    guarded = []
    if sys.platform == "win32":
        for loader_name in ("oledll", "windll"):
            if getattr(ctypes, loader_name, None) is not None:
                setattr(
                    ctypes,
                    loader_name,
                    _BlockedComLoader("ctypes." + loader_name),
                )
                guarded.append("ctypes." + loader_name)
        for factory_name in ("OleDLL", "WinDLL"):
            if getattr(ctypes, factory_name, None) is not None:
                setattr(
                    ctypes,
                    factory_name,
                    _BlockedComLoader("ctypes." + factory_name),
                )
                guarded.append("ctypes." + factory_name)
    return guarded


COM_GUARDED = _install_com_activation_sentinel()


# --- observation helpers ----------------------------------------------------
def forbidden_loaded():
    loaded = []
    for module_name in list(sys.modules):
        if module_name.split(".")[0] in FORBIDDEN_MODULES:
            loaded.append(module_name)
    return sorted(loaded)


def snapshot_cwd():
    return sorted(os.listdir(os.getcwd()))


def finish(code):
    verdict = {
        "scenario": SCENARIO,
        "ok": code == 0,
        "violations": violations,
        "sentinel_fired": SENTINEL_FIRED,
        "com_guarded": COM_GUARDED,
        "forbidden_loaded": forbidden_loaded(),
        "cwd_before": CWD_BEFORE,
        "cwd_after": snapshot_cwd(),
        "caps": CAPS,
        "unexpected": UNEXPECTED,
    }
    print("DBF_PURITY_VERDICT:" + json.dumps(verdict), flush=True)
    sys.exit(code)


CWD_BEFORE = snapshot_cwd()
CAPS = None
UNEXPECTED = None
SENTINEL_FIRED = False
NEGATIVE_SCENARIOS = ("forbidden-import-negative", "com-activation-negative")

try:
    if SCENARIO == "forbidden-import-negative":
        # NEGATIVE CONTROL: deliberately attempt a forbidden dynamic
        # resolution/import (the exact shape an optional-import fallback could
        # hide while leaving sys.modules clean).  The sentinel must intercept
        # the attempt, record the violation and prevent the module load.
        try:
            importlib.import_module("win32com")
        except SentinelViolation:
            SENTINEL_FIRED = True
        else:
            UNEXPECTED = "forbidden import was not intercepted"
    elif SCENARIO == "com-activation-negative":
        # NEGATIVE CONTROL: deliberately invoke the guarded COM/OLE activation
        # entry points.  The sentinel must fire BEFORE any real library load
        # or COM object instantiation.  Windows exercises the real loader and
        # factory routes; other platforms exercise the deterministic sentinel
        # abstraction (no real COM/OLE entry points exist to guard there).
        if sys.platform == "win32":
            probes = (
                ("loader-access", lambda: ctypes.windll.probe_com_object),
                ("factory-call", lambda: ctypes.OleDLL("probe.dll")),
            )
        else:
            probes = (
                ("attribute-access",
                 lambda: _BlockedComLoader("sentinel.com-probe").probe),
                ("factory-call",
                 lambda: _BlockedComLoader("sentinel.com-probe")("probe.dll")),
            )
        for probe_label, trigger in probes:
            try:
                trigger()
            except SentinelViolation:
                SENTINEL_FIRED = True
            else:
                UNEXPECTED = (
                    "COM/OLE activation was not intercepted (%s)" % probe_label
                )
    else:
        if SCENARIO == "capabilities":
            import dbfbridge

            for data_operation in (
                "inspect_table",
                "read_schema",
                "iter_records",
                "iter_raw_records",
                "write_table",
            ):
                setattr(dbfbridge, data_operation, _blocked(data_operation,
                                                            "dbfbridge-data-op"))

        import dbf_anonymizer

        if SCENARIO == "capabilities":
            from dbf_anonymizer import capabilities as capabilities_function

            result = capabilities_function()
            payload = result.to_dict()
            payload_again = dbf_anonymizer.capabilities().to_dict()
            dumped = json.dumps(payload)
            reparsed = json.loads(dumped)
            CAPS = {
                "direct_read": result.direct_read,
                "direct_write": result.direct_write,
                "recovery": result.recovery,
                "transfer_bundle": result.transfer_bundle,
                "vfp_index_backend": result.vfp_index_backend,
                "dbfbridge_version": result.dbfbridge_version,
                "dict_keys": sorted(payload),
                "deterministic": payload == payload_again,
                "json_safe": isinstance(reparsed, dict) and reparsed == payload,
                "path_like_values": [
                    value
                    for value in payload.values()
                    if isinstance(value, str)
                    and (
                        "/" in value
                        or "\\" in value
                        or (len(value) > 1 and value[1] == ":")
                    )
                ],
            }
except SentinelViolation:
    finish(3)
except BaseException as exc:
    UNEXPECTED = "%s: %s" % (type(exc).__name__, exc)
    finish(4)

if SCENARIO in NEGATIVE_SCENARIOS:
    negative_ok = (
        SENTINEL_FIRED
        and UNEXPECTED is None
        and not forbidden_loaded()
        and CWD_BEFORE == snapshot_cwd()
    )
    if SCENARIO == "forbidden-import-negative":
        negative_ok = negative_ok and violations == [
            "forbidden-import: win32com"
        ]
        negative_ok = negative_ok and "win32com" not in sys.modules
    else:
        negative_ok = (
            negative_ok
            and len(violations) == 2
            and all(item.startswith("com-activation") for item in violations)
        )
    finish(0 if negative_ok else 3)

if violations:  # authoritative even if the code under test swallowed the raise
    finish(3)
if forbidden_loaded():
    finish(3)
if CWD_BEFORE != snapshot_cwd():
    finish(3)

finish(0)
'''


def _run_isolated_purity_child(tmp_path: Path, scenario: str) -> tuple[dict, subprocess.CompletedProcess[str]]:
    """Run one isolated purity scenario in a fresh ``-I`` Python interpreter.

    The harness (this pytest process) creates the child script and the empty
    watched directory; the child itself must not create anything.  The
    scenario is a bare package import, a capability discovery call or one of
    the sentinel negative-control probes.
    """
    script_path = tmp_path / "_p1_007_purity_child.py"
    script_path.write_text(CHILD_SCRIPT, encoding="utf-8")
    watched = tmp_path / "watched"
    watched.mkdir()
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["DBF_PURITY_FORBIDDEN_MODULES"] = FORBIDDEN_BACKEND_MODULES
    completed = subprocess.run(
        [sys.executable, "-I", "-X", "utf8", str(script_path), scenario],
        cwd=str(watched),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    verdict_lines = [
        line[len(VERDICT_PREFIX) :]
        for line in completed.stdout.splitlines()
        if line.startswith(VERDICT_PREFIX)
    ]
    assert len(verdict_lines) == 1, (
        f"isolated purity child did not emit exactly one verdict "
        f"(returncode={completed.returncode})\nstdout={completed.stdout!r}\n"
        f"stderr={completed.stderr!r}"
    )
    verdict = json.loads(verdict_lines[0])
    return verdict, completed


def _assert_clean(verdict: dict, completed: subprocess.CompletedProcess[str]) -> None:
    assert completed.returncode == 0, (
        f"isolated purity child failed\nverdict={verdict!r}\n"
        f"stderr={completed.stderr!r}"
    )
    assert verdict["ok"] is True, verdict
    assert verdict["violations"] == [], verdict
    assert verdict["sentinel_fired"] is False, verdict
    assert verdict["forbidden_loaded"] == [], verdict
    assert verdict["unexpected"] is None, verdict
    assert verdict["cwd_before"] == [], verdict
    assert verdict["cwd_after"] == [], verdict
    # The Windows COM/OLE activation sentinel must have been live inside the
    # child before the code under test ran; other platforms have no COM/OLE
    # loader entry points to guard.
    if sys.platform == "win32":
        assert "ctypes.windll" in verdict["com_guarded"], verdict
        assert "ctypes.oledll" in verdict["com_guarded"], verdict
        assert "ctypes.OleDLL" in verdict["com_guarded"], verdict
        assert "ctypes.WinDLL" in verdict["com_guarded"], verdict
    else:
        assert verdict["com_guarded"] == [], verdict


def test_req_p1_007_isolated_import_purity(tmp_path: Path) -> None:
    """A fresh ``import dbf_anonymizer`` violates no sentinel."""
    verdict, completed = _run_isolated_purity_child(tmp_path, "import")
    _assert_clean(verdict, completed)


def test_req_p1_007_isolated_capability_purity(tmp_path: Path) -> None:
    """A fresh ``from dbf_anonymizer import capabilities; capabilities()``
    violates no sentinel, invokes no dbfbridge data operation and returns
    the truthful public model."""
    verdict, completed = _run_isolated_purity_child(tmp_path, "capabilities")
    _assert_clean(verdict, completed)

    caps = verdict["caps"]
    assert caps is not None
    assert sorted(caps["dict_keys"]) == sorted(_EXPECTED_CAPABILITY_KEYS)
    assert caps["deterministic"] is True
    assert caps["json_safe"] is True
    assert caps["path_like_values"] == []

    # Truthful capability facts (REQ-P1-007): the protected canonical dataset
    # recovery (REQ-P5-002/REQ-P5-003) is a REAL implemented service derived
    # from the same required direct read/write runtime capability facts, so
    # a supported dbfbridge[write] environment truthfully reports True
    # without any filesystem probing. Transfer bundles and the VFP index
    # backend stay false until their owning requirements exist.
    assert caps["recovery"] == (
        caps["direct_read"] and caps["direct_write"]
    )
    assert caps["transfer_bundle"] == (
        caps["direct_read"] and caps["direct_write"]
    )
    assert caps["vfp_index_backend"] is False

    # The isolated discovery must agree with the parent-process environment
    # truth (same interpreter distribution; no hard-coded capability claim).
    reference = dbf_anonymizer.capabilities()
    assert caps["direct_read"] == reference.direct_read
    assert caps["direct_write"] == reference.direct_write
    assert caps["dbfbridge_version"] == reference.dbfbridge_version


def test_req_p1_007_forbidden_import_sentinel_negative_control(
    tmp_path: Path,
) -> None:
    """NEGATIVE CONTROL — the forbidden-import sentinel is live.

    The isolated child deliberately attempts a dynamic resolution/import of
    the forbidden COM root ``win32com`` (``importlib.import_module``; the
    exact shape an optional-import fallback could hide while leaving
    ``sys.modules`` clean).  This test passes only because the runtime
    sentinel intercepts the attempt, records the violation and prevents the
    module from actually loading.
    """
    verdict, completed = _run_isolated_purity_child(
        tmp_path, "forbidden-import-negative"
    )
    assert completed.returncode == 0, (
        f"forbidden-import negative control failed\nverdict={verdict!r}\n"
        f"stderr={completed.stderr!r}"
    )
    assert verdict["ok"] is True
    assert verdict["sentinel_fired"] is True
    assert verdict["violations"] == ["forbidden-import: win32com"]
    assert verdict["forbidden_loaded"] == []
    assert verdict["unexpected"] is None


def test_req_p1_007_com_activation_sentinel_negative_control(
    tmp_path: Path,
) -> None:
    """NEGATIVE CONTROL — the COM/OLE activation sentinel is live.

    The isolated child deliberately invokes the guarded COM/OLE activation
    entry points (on Windows the real ``ctypes.windll`` loader-access and
    ``ctypes.OleDLL`` factory routes; on other platforms the deterministic
    sentinel abstraction).  The sentinel must fire BEFORE any real library
    load or COM object instantiation; no real COM object is ever created.
    """
    verdict, completed = _run_isolated_purity_child(
        tmp_path, "com-activation-negative"
    )
    assert completed.returncode == 0, (
        f"COM activation negative control failed\nverdict={verdict!r}\n"
        f"stderr={completed.stderr!r}"
    )
    assert verdict["ok"] is True
    assert verdict["sentinel_fired"] is True
    assert len(verdict["violations"]) == 2
    assert all(
        violation.startswith("com-activation")
        for violation in verdict["violations"]
    )
    assert verdict["forbidden_loaded"] == []
    assert verdict["unexpected"] is None


# ---------------------------------------------------------------------------
# In-process (ordinary pytest) evidence
# ---------------------------------------------------------------------------
def test_capabilities_returns_the_immutable_public_model() -> None:
    result = dbf_anonymizer.capabilities()
    assert isinstance(result, Capabilities)


def test_capabilities_to_dict_is_deterministic_json_safe_and_leak_free() -> None:
    result = dbf_anonymizer.capabilities()
    payload = result.to_dict()
    assert payload == dbf_anonymizer.capabilities().to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert set(payload) == _EXPECTED_CAPABILITY_KEYS
    assert payload["model_type"] == "Capabilities"
    # REQ-P1-007 truthfulness: the implemented REQ-P5-002/REQ-P5-003
    # recovery service derives its capability from the same required direct
    # read/write runtime facts.
    assert payload["recovery"] == (
        result.direct_read and result.direct_write
    )
    assert payload["transfer_bundle"] == (
        result.direct_read and result.direct_write
    )
    assert payload["vfp_index_backend"] is False
    for key, value in payload.items():
        if isinstance(value, str):
            assert "/" not in value and "\\" not in value, (key, value)
            assert not (len(value) > 1 and value[1] == ":"), (key, value)


def test_capability_discovery_never_invokes_dbfbridge_data_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dbfbridge

    calls: list[str] = []

    for operation in DBFBRIDGE_DATA_OPERATIONS:
        def _guard(*args: object, _operation: str = operation, **kwargs: object) -> None:
            calls.append(_operation)
            raise AssertionError(
                f"capability discovery invoked dbfbridge.{_operation}"
            )

        monkeypatch.setattr(dbfbridge, operation, _guard, raising=False)  # type: ignore[attr-defined]

    result = dbf_anonymizer.capabilities()
    assert calls == []
    assert isinstance(result, Capabilities)


def test_import_and_discovery_load_no_com_or_vfp_backend_modules() -> None:
    before = set(sys.modules)
    dbf_anonymizer.capabilities()
    added = set(sys.modules) - before
    loaded = sorted(
        name
        for name in added
        if name.split(".")[0] in FORBIDDEN_BACKEND_MODULES.split(",")
    )
    assert loaded == []
    assert dbf_anonymizer.capabilities().vfp_index_backend is False
