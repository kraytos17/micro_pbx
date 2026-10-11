"""Live interop scenarios against the PBX over loopback UDP.

Replaces interop/run.sh 1:1 (same scenarios, same ordering, same log
archive layout). Execution order is file order; test_no_errors must stay
last — it asserts the whole run's PBX log is error-free.

Fast set (~10s): register (plain/qop/negative/unknown-user), S3, S7,
garbage resilience, unregister, S4+S5, S6, callee-BYE. S8 (Timer-B 408,
~40s) is slow.
"""

import socket
import time

import pytest

from conftest import (
    PBX_HOST,
    PBX_PORT,
    SILENT_PORT,
    UAC_PORT,
    UAS_PORT,
    expect_log_growth,
    expect_no_log_growth,
    run_sipp_uac,
    sipp_uas,
)
from register import RegisterError, bare_register_status, register
from sipassert import assert_sipp_ok, parse_sipp_msg_log, via_branches


def test_s1_register(pbx, logs_dir):
    """S1: baseline REGISTER (401 challenged, 200 accepted)."""
    register("alice", "alicepass", UAC_PORT)


def test_s1_register_qop(pbx, logs_dir):
    """S1q: same handshake answering with qop=auth (covers qop path live)."""
    register("alice", "alicepass", UAC_PORT, use_qop=True)


def test_register_wrong_password_fails(pbx, logs_dir):
    """Negative control: bad credentials must not register (no 200)."""
    with pytest.raises(RegisterError):
        register("alice", "wrongpass", UAC_PORT)


def test_register_unknown_user_challenged(pbx, logs_dir):
    """Unknown-user REGISTER is challenged (401 + nonce), never 404:
    no user enumeration, live."""
    status, msg = bare_register_status("nobody", UAC_PORT)
    assert status.startswith("SIP/2.0 401"), (
        f"want 401 challenge for unknown user, got: {status}")
    assert "nonce=" in msg, "401 challenge lacks nonce"


def test_s3_unknown(pbx, logs_dir):
    """S3: unknown user -> 404 once; the duplicate INVITE's replay is
    asserted via the PBX log (sipp discards it: its own INVITE transaction
    already completed on the first 404)."""
    with expect_log_growth(logs_dir, "retransmission detected"):
        run_sipp_uac(logs_dir, "s3-unknown", "uac-unknown.xml")


def test_s7_max_forwards(pbx, logs_dir):
    """S7: exhausted Max-Forwards -> 483, no dialog."""
    run_sipp_uac(logs_dir, "s7-max-forwards", "uac-mf0.xml")


def test_garbage_datagrams_ignored(pbx, logs_dir):
    """Binary/truncated/empty datagrams: parse warns, PBX stays responsive,
    no error-level log."""
    with expect_no_log_growth(logs_dir, "] error("):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for payload in (b"\xff\x00\xfe\x01binary garbage\x02",
                            b"INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\nVia: tru",
                            b""):
                sock.sendto(payload, (PBX_HOST, PBX_PORT))
            time.sleep(0.5)
        finally:
            sock.close()
        # Liveness: a full REGISTER handshake still works afterwards.
        register("alice", "alicepass", UAC_PORT)


def test_unregister_then_unreachable(pbx, logs_dir):
    """Expires:0 deletes the contact: calls to alice 404 until re-registered.
    State is restored at the end for later scenarios."""
    register("alice", "alicepass", UAC_PORT)
    register("alice", "alicepass", UAC_PORT, expires=0)
    run_sipp_uac(logs_dir, "unregistered", "uac-unregistered.xml")
    register("alice", "alicepass", UAC_PORT)


def test_s4_call_and_s5_absorb(pbx, logs_dir):
    """S4+S5: full call; the caller sends a duplicate INVITE mid-dialog
    that the PBX must absorb (second 100, no re-forward).

    Bob registers first (foreground, deterministic order), then the dialog
    UAS listens on the same port.
    """
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "s4-call", "uas-answer.xml", UAS_PORT) as uas:
            time.sleep(1)
            run_sipp_uac(logs_dir, "s4-call", "uac-alice-call.xml")
        assert uas.returncode == 0, "s4 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s4-call-uas-out.txt")

        # S5: distinct PBX Via branches on INVITEs only (ACK/BYE mint fresh
        # PBX branches by design; Timer-A retransmits share one). Any second
        # branch here would prove a caller retransmit was re-forwarded.
        msgs = parse_sipp_msg_log(logs_dir / "s4-call-uas-msg.log")
        invites = [m for m in msgs
                   if m.direction == "received" and m.is_request("INVITE")]
        branches = {b for m in invites
                    for b in via_branches(m, f"127.0.0.1:{PBX_PORT}")}
        assert len(branches) == 1, (
            f"s5-absorb: want 1 PBX branch, got {sorted(branches)} "
            f"across {len(invites)} INVITEs")


def test_s6_cancel(pbx, logs_dir):
    """S6: CANCEL race (bob re-registers first; same port as dialog UAS)."""
    with expect_log_growth(logs_dir, "terminated (487)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "s6-cancel", "uas-cancel.xml",
                       UAS_PORT) as uas:
            time.sleep(1)
            run_sipp_uac(logs_dir, "s6-cancel", "uac-alice-cancel.xml")
        assert uas.returncode == 0, "s6 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s6-cancel-uas-out.txt")


def test_callee_bye(pbx, logs_dir):
    """Mirror teardown: the callee hangs up (BYE from bob), the caller
    answers 200. Bob re-registers first, same port as the dialog UAS."""
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "callee-bye", "uas-answer-bye.xml",
                       UAS_PORT) as uas:
            time.sleep(1)
            run_sipp_uac(logs_dir, "callee-bye", "uac-alice-callee-bye.xml")
        assert uas.returncode == 0, "callee-bye UAS exited non-zero"
        assert_sipp_ok(logs_dir / "callee-bye-uas-out.txt")


@pytest.mark.slow
def test_s8_timer_b(pbx, logs_dir):
    """S8: silent contact -> Timer B 408 (~32s). Longer sipp global timeout
    than the default: the 408 arrives 32s in."""
    with expect_log_growth(logs_dir, "terminated (408"):
        register("silent", "silentpass", SILENT_PORT)
        run_sipp_uac(logs_dir, "s8-invite-silent", "uac-invite-silent.xml",
                     timeout_s=50)


# Must stay last: asserts the whole run left no error-level PBX log behind
# (retransmit/send failures, sweep failures and OOM paths all log here).
def test_no_errors(pbx, logs_dir):
    text = (logs_dir / "pbx.log").read_text(errors="replace")
    errors = [l for l in text.splitlines() if "] error(" in l]
    assert not errors, f"{len(errors)} error lines in pbx log: {errors[:5]}"
