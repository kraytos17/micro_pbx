"""Shared interop fixtures: PBX lifecycle, per-run log archiving, sipp runners.

Usage:
  uv run pytest            # fast set (S1,S3,S4+S5,S6,S7), ~15s
  uv run pytest --run-slow # + S8 Timer-B 408, ~40s extra
  uv run pytest -k s4      # select scenarios by name substring
"""

import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sipassert import assert_sipp_ok

PBX_HOST = "127.0.0.1"
PBX_PORT = 5060
UAS_PORT = 5070
UAC_PORT = 5061
# Silent-contact port: nothing listens here, so INVITEs to it go unanswered.
# Must differ from UAC_PORT, or the PBX (which routes by source address)
# would forward the INVITE back to the caller itself.
SILENT_PORT = 5063
# Loopback port reservations: unit tests (src/pbx.zig) emit real UDP and own
# 5090/5092. Never move these ports into that range; sipp aborts on any
# unexpected datagram, so a collision flakes this suite. Run the two suites
# serially — never `zig test` and pytest concurrently.

ROOT = Path(__file__).resolve().parent.parent
INT = Path(__file__).resolve().parent


def pytest_addoption(parser):
    parser.addoption("--run-slow", action="store_true", default=False,
                     help="include slow scenarios (S8 Timer-B 408)")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-slow"):
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(pytest.mark.skip(reason="needs --run-slow"))


@pytest.fixture(scope="session")
def logs_dir():
    """Timestamped per-run archive + `latest` symlink (run.sh convention)."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    d = INT / "logs" / run_id
    d.mkdir(parents=True)
    latest = INT / "logs" / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(run_id)
    return d


@pytest.fixture(scope="session")
def pbx(logs_dir):
    """Build, spawn the PBX, wait for readiness (bounded), teardown after.

    The PBX loads interop/users.conf explicitly (same users as the seeds),
    so every run exercises the file path live; unit tests cover the loader.
    """
    subprocess.run(["zig", "build"], cwd=ROOT, check=True)
    log_path = logs_dir / "pbx.log"
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [str(ROOT / "zig-out" / "bin" / "micro_pbx"),
             str(INT / "users.conf")],
            stdout=logf, stderr=subprocess.STDOUT)
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                if proc.poll() is not None:
                    pytest.fail(f"PBX exited during startup (see {log_path})")
                if "PBX listening on" in log_path.read_text(errors="replace"):
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"PBX never became ready (see {log_path})")
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _sipp_base(xml, port, timeout_s):
    return ["sipp", f"{PBX_HOST}:{PBX_PORT}", "-i", PBX_HOST, "-p", str(port),
            "-sf", str(INT / xml), "-m", "1",
            "-timeout", f"{timeout_s}s", "-timeout_error"]


def run_sipp_uac(logs_dir, name, xml, timeout_s=30):
    """Run a caller scenario; assert green counters (exit codes lie)."""
    cmd = _sipp_base(xml, UAC_PORT, timeout_s) + [
        "-trace_msg", "-message_file", str(logs_dir / f"{name}-uac-msg.log"),
        "-trace_err", "-error_file", str(logs_dir / f"{name}-uac-err.log"),
        "-log_file", str(logs_dir / f"{name}-uac.log")]
    with open(logs_dir / f"{name}-out.txt", "wb") as out:
        # Backstop beyond sipp's own -timeout: never hang the suite.
        subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT,
                       timeout=timeout_s + 30, check=False)
    assert_sipp_ok(logs_dir / f"{name}-out.txt")


@contextmanager
def sipp_uas(logs_dir, name, xml, port, extra=()):
    """Run a callee scenario in the background; always reaped.

    Yields the Popen handle; on exit waits (bounded) for its natural end,
    killing on hang so one stuck scenario can't wedge the suite. Callers
    must still assert returncode == 0 and green counters afterwards —
    Popen alone can't tell pass from fail. `extra` appends raw sipp flags
    (e.g. RTP echo/media pinning for media tests).
    """
    cmd = _sipp_base(xml, port, 60) + [
        "-trace_msg", "-message_file", str(logs_dir / f"{name}-uas-msg.log"),
        "-trace_err", "-error_file", str(logs_dir / f"{name}-uas-err.log"),
        "-log_file", str(logs_dir / f"{name}-uas.log")] + list(extra)
    with open(logs_dir / f"{name}-uas-out.txt", "wb") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)
    try:
        yield proc
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise


@contextmanager
def expect_log_growth(logs_dir, needle):
    """Assert a pbx.log pattern grows inside the block (log is cumulative)."""
    log_path = logs_dir / "pbx.log"
    before = log_path.read_text(errors="replace").count(needle)
    yield
    after = log_path.read_text(errors="replace").count(needle)
    assert after > before, f"no '{needle}' growth in pbx log"


@contextmanager
def expect_no_log_growth(logs_dir, needle):
    """Assert a pbx.log pattern does NOT grow inside the block (mirror of
    expect_log_growth, for must-stay-clean invariants like error lines)."""
    log_path = logs_dir / "pbx.log"
    before = log_path.read_text(errors="replace").count(needle)
    yield
    after = log_path.read_text(errors="replace").count(needle)
    assert after == before, f"'{needle}' grew by {after - before} in pbx log"
