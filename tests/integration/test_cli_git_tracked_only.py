"""--git_tracked_only: option wiring, non-git usage error, and fingerprints equal to a normal scan."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile

import pytest
import yaml

import dsoinabox.cli as cli
import dsoinabox.run as run_mod
from dsoinabox.cli import main
from dsoinabox.policy import EXIT_SCANNER, EXIT_USAGE


def git(repo, *args):
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "init.defaultBranch=main",
                    *args], cwd=repo, check=True, capture_output=True)


# --- option wiring ----------------------------------------------------------


@pytest.fixture
def captured(monkeypatch):
    seen = {}

    def fake_run(options):
        seen["options"] = options
        raise run_mod.UsageError("stop here")

    monkeypatch.setattr(cli, "run_scan", fake_run)
    return seen


@pytest.mark.parametrize("how", ["default", "snake", "kebab", "env", "config"])
def test_option_sources(how, captured, monkeypatch, tmp_path):
    argv = ["--source", str(tmp_path), "--report_directory", str(tmp_path / "r"), "--project_id", "p"]
    if how == "snake":
        argv.append("--git_tracked_only")
    elif how == "kebab":
        argv.append("--git-tracked-only")
    elif how == "env":
        monkeypatch.setenv("DSOINABOX_GIT_TRACKED_ONLY", "true")
    elif how == "config":
        (tmp_path / ".dsoinabox.yaml").write_text("git_tracked_only: true\n")
    assert main(argv) == EXIT_USAGE
    assert captured["options"].git_tracked_only is (how != "default")


def test_env_false_overrides_config(captured, monkeypatch, tmp_path):
    (tmp_path / ".dsoinabox.yaml").write_text("git_tracked_only: true\n")
    monkeypatch.setenv("DSOINABOX_GIT_TRACKED_ONLY", "false")
    main(["--source", str(tmp_path), "--report_directory", str(tmp_path / "r"), "--project_id", "p"])
    assert captured["options"].git_tracked_only is False


# --- fake scanners that walk the tree like the real ones --------------------


def _walk(source, cwd):
    root = os.path.join(cwd or os.getcwd(), source)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            yield full, os.path.relpath(full, root)


def _dump(data, out_dir, name):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, name), "w") as fd:
        json.dump(data, fd, indent=4)


@pytest.fixture
def scanners(monkeypatch):
    import dsoinabox.scanners.base as base
    import dsoinabox.scanners.iac.checkov as checkov
    import dsoinabox.scanners.sast.opengrep as opengrep
    import dsoinabox.scanners.sbom.syft as syft
    import dsoinabox.scanners.sca.grype as grype
    import dsoinabox.scanners.secrets.trufflehog as trufflehog
    import dsoinabox.utils.environment

    calls: list[tuple[str, str, str | None]] = []

    def fake_opengrep(source, extra, out_dir, timeout=None, opengrep_rules=None, cwd=None):
        calls.append(("opengrep", source, cwd))
        results, scanned = [], []
        for full, rel in _walk(source, cwd):
            path = os.path.normpath(os.path.join(source, rel))  # opengrep prints paths under the argument
            scanned.append(path)
            for n, line in enumerate(open(full, errors="replace").read().splitlines(), 1):
                col = line.find("os.system")
                if col >= 0:
                    results.append({"check_id": "py.os-system", "path": path,
                                    "start": {"line": n, "col": col + 1}, "end": {"line": n, "col": len(line) + 1},
                                    "extra": {"severity": "HIGH", "message": "m", "lines": line}})
        data = {"results": results, "paths": {"scanned": scanned}}
        _dump(data, out_dir, "opengrep.json")
        return data

    def fake_checkov(source, extra, out_dir, timeout=None, cwd=None):
        calls.append(("checkov", source, cwd))
        base_dir = cwd or os.getcwd()
        results = []
        for full, rel in _walk(source, cwd):
            if rel.endswith(".tf") and "public-read" in open(full).read():
                # checkov: "/" + relpath(file, cwd) with "/.." dropped, written without the leading slash
                uri = ("/" + os.path.relpath(os.path.abspath(full), base_dir)).replace("/..", "").lstrip("/")
                results.append({"ruleId": "CKV_AWS_20", "level": "error", "message": {"text": "public"},
                                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                                    "region": {"startLine": 1, "endLine": 3,
                                                                               "snippet": {"text": "acl"}}}}]})
        return {"runs": [{"tool": {"driver": {"rules": []}}, "results": results}]}

    def fake_syft(source, extra, out_dir, timeout=None, cwd=None):
        calls.append(("syft", source, cwd))
        artifacts = []
        for full, rel in _walk(source, cwd):
            if os.path.basename(rel) == "requirements.txt":
                for line in open(full).read().splitlines():
                    name, _, version = line.partition("==")
                    artifacts.append({"id": hashlib.sha256(f"{rel}{line}".encode()).hexdigest()[:16], "name": name,
                                      "version": version, "type": "python", "locations": [{"path": "/" + rel}]})
        data = {"artifacts": artifacts, "source": {"id": hashlib.sha256(source.encode()).hexdigest(), "name": source,
                                                   "type": "directory", "metadata": {"path": source}}}
        _dump(data, out_dir, "syft.json")
        return data

    def fake_grype(source, extra, out_dir, timeout=None, db_mode="auto", db_cache=None, always_update=False, cwd=None):
        calls.append(("grype", source, cwd))
        with open(os.path.join(out_dir, "syft.json")) as fd:
            sbom = json.load(fd)
        matches = [{"vulnerability": {"id": f"CVE-{a['name']}", "severity": "High", "namespace": "ns"}, "artifact": a}
                   for a in sbom["artifacts"]]
        data = {"matches": matches, "source": {"type": "directory", "target": sbom["source"]["name"]}}
        _dump(data, out_dir, "grype.json")
        return data

    def fake_trufflehog(source, extra, out_dir, timeout=None, git_repo=True, verify=False, cwd=None):
        calls.append(("trufflehog", source, cwd))
        return []

    monkeypatch.setattr(opengrep, "run_scan", fake_opengrep)
    monkeypatch.setattr(checkov, "run_scan", fake_checkov)
    monkeypatch.setattr(syft, "run_scan", fake_syft)
    monkeypatch.setattr(grype, "run_scan", fake_grype)
    monkeypatch.setattr(trufflehog, "run_scan", fake_trufflehog)
    monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "no version probes in tests"))
    return calls


@pytest.fixture
def isolated_tmp(tmp_path, monkeypatch):
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    return tmp


@pytest.fixture
def dirty_repo(tmp_path, isolated_tmp):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "infra").mkdir()
    (repo / ".gitignore").write_text("build/\n")
    (repo / "src" / "app.py").write_text("import os\nos.system('ls ' + x)\n")
    (repo / "infra" / "s3.tf").write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    (repo / "requirements.txt").write_text("requests==2.19.1\n")
    (repo / "README.md").write_text("tracked, deleted below\n")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    # uncommitted edit and deletion of tracked files: the scan must see the working tree
    with open(repo / "src" / "app.py", "a") as fd:
        fd.write("os.system('rm ' + y)\n")
    (repo / "README.md").unlink()
    # untracked and ignored junk
    (repo / "venv" / "lib").mkdir(parents=True)
    (repo / "venv" / "lib" / "requirements.txt").write_text("django==1.2\n")
    (repo / "venv" / "tool.py").write_text("import os\nos.system(z)\n")
    (repo / "build").mkdir()
    (repo / "build" / "main.tf").write_text('resource "aws_s3_bucket" "j" {\n  acl = "public-read"\n}\n')
    (repo / "untracked.py").write_text("import os\nos.system(w)\n")
    return repo


JUNK = ("venv", "build", "untracked.py")


def _scan(repo_arg, reports, *extra):
    code = main(["--source", repo_arg, "-t", "all", "-o", "json,sarif", "--tool_output", "--report_name", "r",
                 "--report_directory", str(reports), "--project_id", "p", *extra])
    report_dir = next(p for p in reports.iterdir() if p.name.startswith("dsoinabox_"))
    return code, report_dir, json.loads((report_dir / "r.json").read_text())


def _fingerprints(data):
    out: dict[str, set[str]] = {}
    for f in data["findings"]:
        out.setdefault(f["tool"], set()).update(f["fingerprints"].values())
    return out


@pytest.mark.integration
@pytest.mark.parametrize("form", ["absolute", "relative"])
def test_tracked_only_matches_normal_scan_of_clean_tree(form, dirty_repo, scanners, isolated_tmp, tmp_path,
                                                        monkeypatch):
    if form == "relative":
        monkeypatch.chdir(dirty_repo)
        repo_arg = "."
    else:
        repo_arg = str(dirty_repo)

    code, tracked_dir, tracked = _scan(repo_arg, tmp_path / "reports_tracked", "--git_tracked_only")
    assert code == 0
    walked = [c for c in scanners if c[0] != "trufflehog"]
    assert walked and all(c[2] is not None and c[2].startswith(str(isolated_tmp)) for c in walked)
    assert [c for c in scanners if c[0] == "trufflehog"] == [("trufflehog", repo_arg, None)]
    assert os.listdir(isolated_tmp) == [], "the tracked copy must be removed after the scan"

    paths = {f["path"] for f in tracked["findings"]}
    assert paths == {"src/app.py", "infra/s3.tf", "requirements.txt"}
    assert {f["start_line"] for f in tracked["findings"] if f["tool"] == "opengrep"} == {2, 3}
    assert tracked["metadata"]["source"] == repo_arg

    for name in JUNK:
        target = dirty_repo / name
        shutil.rmtree(target) if target.is_dir() else target.unlink()
    scanners.clear()
    code, normal_dir, normal = _scan(repo_arg, tmp_path / "reports_normal")
    assert code == 0
    assert all(c[2] is None for c in scanners), "without the option scanners get no working directory override"

    assert _fingerprints(tracked) == _fingerprints(normal)
    assert len(tracked["findings"]) == len(normal["findings"])
    for name in ("opengrep.json", "syft.json", "grype.json"):
        assert (tracked_dir / "tools_output" / name).read_text() == (normal_dir / "tools_output" / name).read_text()
    sarif = [json.loads((d / "r.sarif").read_text())["runs"] for d in (tracked_dir, normal_dir)]
    assert [r.get("results") for r in sarif[0]] == [r.get("results") for r in sarif[1]]


@pytest.mark.integration
def test_tracked_copy_removed_when_a_scanner_fails(dirty_repo, scanners, isolated_tmp, tmp_path, monkeypatch):
    import dsoinabox.scanners.sast.opengrep as opengrep

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("opengrep", 1)

    monkeypatch.setattr(opengrep, "run_scan", timeout)
    code, _report_dir, _data = _scan(str(dirty_repo), tmp_path / "reports", "--git_tracked_only")
    assert code == EXIT_SCANNER
    assert os.listdir(isolated_tmp) == []


@pytest.mark.integration
def test_non_git_source_is_a_usage_error(scanners, isolated_tmp, tmp_path):
    source = tmp_path / "plain"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    reports = tmp_path / "reports"
    code = main(["--source", str(source), "--report_directory", str(reports), "--project_id", "p",
                 "--git_tracked_only"])
    assert code == EXIT_USAGE
    assert scanners == []
    assert os.listdir(isolated_tmp) == []


@pytest.mark.integration
def test_config_file_enables_tracked_only(dirty_repo, scanners, tmp_path):
    (dirty_repo / ".dsoinabox.yaml").write_text(yaml.safe_dump({"git_tracked_only": True}))
    code, _report_dir, data = _scan(str(dirty_repo), tmp_path / "reports", "-t", "opengrep")
    assert code == 0
    assert {f["path"] for f in data["findings"]} == {"src/app.py"}


@pytest.mark.integration
def test_trufflehog_filesystem_mode_uses_the_copy(dirty_repo, scanners, isolated_tmp, tmp_path):
    # a repository subdirectory is no .git root, so TruffleHog walks files instead of reading history
    source = str(dirty_repo / "src")
    code, _report_dir, _data = _scan(source, tmp_path / "reports", "-t", "secret", "--git_tracked_only")
    assert code == 0
    [(tool, arg, cwd)] = scanners
    assert tool == "trufflehog" and cwd is not None and arg.startswith(str(isolated_tmp)) and arg.endswith(source)


@pytest.mark.integration
def test_untracked_subdirectory_source_is_a_usage_error(dirty_repo, scanners, isolated_tmp, tmp_path):
    # venv/ is untracked: a normal scan would report its findings, a tracked-only scan must not pass silently
    code = main(["--source", str(dirty_repo / "venv"), "--report_directory", str(tmp_path / "reports"),
                 "--project_id", "p", "--git_tracked_only"])
    assert code == EXIT_USAGE
    assert scanners == []
    assert os.listdir(isolated_tmp) == []


@pytest.mark.integration
def test_git_reason_is_shown_when_source_is_rejected(scanners, tmp_path, monkeypatch):
    import dsoinabox.run as run_module

    monkeypatch.setattr(run_module, "git_work_tree_problem",
                        lambda path: "fatal: detected dubious ownership in repository at '/scan_target'")
    options = run_module.ScanOptions(source=str(tmp_path), report_directory=str(tmp_path / "r"), timestamp="t",
                                     project_id="p", git_tracked_only=True)
    with pytest.raises(run_module.UsageError, match="dubious ownership"):
        run_module.run_scan(options)
    assert scanners == []


@pytest.mark.integration
def test_sigterm_during_tracked_scan_removes_the_copy(dirty_repo, scanners, isolated_tmp, tmp_path, monkeypatch):
    import dsoinabox.scanners.sast.opengrep as opengrep

    before = signal.getsignal(signal.SIGTERM)
    seen = []

    def terminated(*a, **k):
        seen.append(signal.getsignal(signal.SIGTERM))
        os.kill(os.getpid(), signal.SIGTERM)
        return {"results": []}

    monkeypatch.setattr(opengrep, "run_scan", terminated)
    with pytest.raises(SystemExit):
        main(["--source", str(dirty_repo), "-t", "opengrep", "-o", "json", "--report_directory",
              str(tmp_path / "reports"), "--project_id", "p", "--git_tracked_only"])
    assert seen and seen[0] is not before
    assert os.listdir(isolated_tmp) == []
    assert signal.getsignal(signal.SIGTERM) is before


@pytest.mark.integration
def test_default_scan_leaves_sigterm_handler_alone(dirty_repo, scanners, tmp_path, monkeypatch):
    import dsoinabox.scanners.sast.opengrep as opengrep

    before = signal.getsignal(signal.SIGTERM)
    seen = []
    monkeypatch.setattr(opengrep, "run_scan", lambda *a, **k: seen.append(signal.getsignal(signal.SIGTERM)) or
                        {"results": []})
    code, _report_dir, _data = _scan(str(dirty_repo), tmp_path / "reports", "-t", "opengrep")
    assert code == 0
    assert seen == [before]
