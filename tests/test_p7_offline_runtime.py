"""REQ-P7-004 pinned offline wheelhouse and network-free runtime evidence."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tools.check_p7_offline_runtime import run_contract
from tools.check_p7_offline_wheelhouse import (
    EXPECTED_APPLICATION,
    EXPECTED_RUNTIME_PINS,
    _manifest_pins,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "dbf_anonymizer"
MANIFEST = REPO_ROOT / "requirements" / "p7-offline-wheelhouse.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "p0-package-boundary.yml"

NETWORK_MODULES = frozenset(
    {
        "socket",
        "urllib.request",
        "http.client",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "ftplib",
        "smtplib",
        "xmlrpc.client",
    }
)
PACKAGE_INSTALL_MODULES = frozenset(
    {"pip", "ensurepip", "setuptools", "pkg_resources", "venv"}
)
PROCESS_MODULES = frozenset({"subprocess"})
OPTIONAL_PROCESS_MODULES = frozenset({"index_backend.py"})
FORBIDDEN_COMMANDS = frozenset({"pip", "git", "uv", "poetry", "conda"})
PROCESS_CALLS = frozenset(
    {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
    }
)


def _import_names(node: ast.Import | ast.ImportFrom) -> set[str]:
    if isinstance(node, ast.Import):
        return {alias.name for alias in node.names}
    module = node.module or ""
    if module in {"urllib", "http", "xmlrpc"}:
        return {f"{module}.{alias.name}" for alias in node.names}
    return {module} if module else set()


def _literal_strings(node: ast.AST) -> set[str]:
    return {
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                aliases[imported.asname or imported.name.split(".")[0]] = imported.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for imported in node.names:
                aliases[imported.asname or imported.name] = (
                    f"{node.module}.{imported.name}"
                )
    return aliases


def _call_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    root = aliases.get(current.id, current.id)
    return ".".join((root, *reversed(parts)))


def _forbidden_process_commands(source: str) -> list[tuple[int, list[str]]]:
    tree = ast.parse(source)
    aliases = _import_aliases(tree)
    violations: list[tuple[int, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _call_name(node.func, aliases)
        if target is None or not (
            target in PROCESS_CALLS
            or target.startswith("os.spawn")
            or target.startswith("os.exec")
        ):
            continue
        strings = {
            token.casefold()
            for value in _literal_strings(node)
            for token in re.findall(r"[A-Za-z0-9_.-]+", value)
        }
        forbidden = sorted(strings & FORBIDDEN_COMMANDS)
        if forbidden:
            violations.append((node.lineno, forbidden))
    return violations


def test_offline_manifest_pins_the_exact_runtime_dependency_closure() -> None:
    assert _manifest_pins(MANIFEST) == {
        "dbfbridge": "1.1.1",
        "dbfread": "2.0.7",
        "dbf": "0.99.11",
        "aenum": "3.1.17",
    }
    assert EXPECTED_RUNTIME_PINS == _manifest_pins(MANIFEST)
    assert EXPECTED_APPLICATION == {"dbf-anonymizer": "1.0.0.dev0"}
    source = PYPROJECT.read_text(encoding="utf-8")
    assert '"dbfbridge[write]>=1.1.0,<2"' in source


def test_production_has_no_online_runtime_or_package_installer_imports() -> None:
    violations: list[str] = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            imported = _import_names(node)
            forbidden = sorted(imported & (NETWORK_MODULES | PACKAGE_INSTALL_MODULES))
            if forbidden:
                violations.append(f"{relative}:{node.lineno}:{forbidden}")
            if imported & PROCESS_MODULES and path.name not in OPTIONAL_PROCESS_MODULES:
                violations.append(
                    f"{relative}:{node.lineno}:subprocess outside optional backend boundary"
                )
    assert violations == []


def test_production_has_no_git_or_package_manager_command_calls() -> None:
    violations: list[str] = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        relative = path.relative_to(SRC_ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        for line, commands in _forbidden_process_commands(source):
            violations.append(f"{relative}:{line}:{commands}")
    assert violations == []


def test_process_command_guard_is_precise() -> None:
    assert _forbidden_process_commands(
        "import subprocess as sp\nsp.run(['git', 'status'])\n"
    ) == [(2, ["git"])]
    assert _forbidden_process_commands(
        "from subprocess import check_call as launch\n"
        "launch(['python', '-m', 'pip', 'install', 'x'])\n"
    ) == [(2, ["pip"])]
    assert _forbidden_process_commands(
        "import subprocess\nsubprocess.run(['vfp9.exe', '-t', 'job'])\n"
    ) == []
    assert _forbidden_process_commands(
        "raise RuntimeError('git is unavailable')\n"
    ) == []


def test_standalone_workflow_crosses_no_network_or_process_boundary(
    tmp_path: Path,
) -> None:
    evidence = run_contract(
        tmp_path / "offline-runtime",
        require_installed=False,
    )
    assert evidence["network_attempts"] == 0
    assert evidence["process_attempts"] == 0
    assert evidence["dataset_verification"] == "PASS"
    assert evidence["bundle_verified"] is True
    assert evidence["enabled_recovery_verified"] is True
    assert evidence["cli_recovery_policy"] == "PASS"


def test_windows_ci_proves_local_only_clean_offline_installation() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    required_evidence = (
        "P7 offline wheelhouse / clean Windows standalone runtime",
        "requirements/p7-offline-wheelhouse.txt",
        "check_p7_offline_wheelhouse.py",
        "check_p7_offline_runtime.py",
        "--no-index",
        "--find-links",
        "--no-cache-dir",
        "PIP_NO_INDEX",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "python -m venv",
        "python -m pip check",
        "site-packages",
    )
    for evidence in required_evidence:
        assert evidence in workflow
