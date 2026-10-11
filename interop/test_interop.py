"""Live interop scenarios against the PBX over loopback UDP.

Dialog callers are Python (`invite.Dialog` — sipp can't compute digests);
sipp keeps the callee leg and S7. Registration via imported `register()`.
Execution order is file order; test_no_errors must stay last — it asserts
the whole run's PBX log is error-free.

Fast set (~10s): register (plain/qop/negative/unknown-user/replay),
INVITE-unknown-407, S3' (authed 404 + replay), S7, garbage resilience,
S4+S5, S6, callee-BYE ×2. S8 (Timer-B 408, ~40s) is slow.
"""

import os
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
from invite import (
    Dialog,
    InviteError,
    MediaSocket,
    bare_invite_status,
    parse_to_tag,
    rtp_packet,
    sdp_media_port,
)
from register import (
    RegisterError,
    bare_register_status,
    register,
    replay_authorization,
)
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


def test_register_nonce_replay_fails(pbx, logs_dir):
    """Captured Authorization cannot be reused: identical authed REGISTER
    200s once, then gets a fresh 401 (single-use nonces, live)."""
    first, second, second_msg = replay_authorization(
        "alice", "alicepass", UAC_PORT)
    assert first.startswith("SIP/2.0 200"), f"first leg failed: {first}"
    assert second.startswith("SIP/2.0 401"), (
        f"replay accepted, want 401: {second}")
    assert "nonce=" in second_msg, "re-challenge lacks nonce"


def test_invite_unknown_user_challenged(pbx, logs_dir):
    """Unknown-user INVITE is challenged (401 + nonce), never 404 or
    forwarded: auth precedes lookup, so existence never leaks (live)."""
    status, msg = bare_invite_status("nobody", "nobody", UAC_PORT)
    assert status.startswith("SIP/2.0 401"), (
        f"want 401 challenge for unknown user, got: {status}")
    assert "nonce=" in msg, "401 challenge lacks nonce"


def test_s3_unregistered(pbx, logs_dir):
    """S3 (auth era): authed INVITE to an unregistered known user 404s once;
    the duplicate's replay is asserted via the PBX log (retransmits replay
    from the error cache before auth runs, so the consumed nonce is fine).
    Expires:0 deletes the contact; state is restored at the end."""
    register("alice", "alicepass", UAC_PORT)
    register("alice", "alicepass", UAC_PORT, expires=0)
    with expect_log_growth(logs_dir, "retransmission detected"):
        dlg = Dialog("bob", "bobpass", UAC_PORT)
        try:
            call_id = f"pys3-{os.urandom(4).hex()}"
            dlg.call_expect("alice", call_id, "pybob1", "SIP/2.0 404")
            dlg.resend_last()  # same branch: replay, not re-challenge
            try:
                dlg._recv()  # replayed 404, drained and ignored
            except InviteError:
                pass
        finally:
            dlg.close()
    register("alice", "alicepass", UAC_PORT)


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


def test_s4_call_and_s5_absorb(pbx, logs_dir):
    """S4+S5 via Python authed caller + sipp UAS: 401 handshake, full call;
    mid-dialog duplicate INVITE (Timer-A style, same branch) absorbed —
    exactly 1 PBX Via branch at the UAS (no re-forward), BYE teardown.

    Bob registers first (foreground, deterministic order), then the dialog
    UAS listens on the same port.
    """
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "s4-call", "uas-answer.xml", UAS_PORT) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            try:
                call_id = f"pys4-{os.urandom(4).hex()}"
                to_tag, _ = dlg.invite("bob", call_id, "pyalice1")
                assert to_tag, "answer lacks To tag"
                dlg.resend_last()  # S5 storm: duplicate must absorb
                dlg.ack("bob", call_id, "pyalice1", to_tag, 2)
                time.sleep(0.5)
                dlg.bye("bob", call_id, 3, "pyalice1", to_tag)
            finally:
                dlg.close()
        assert uas.returncode == 0, "s4 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s4-call-uas-out.txt")

        # S5: the storm duplicate (same branch) is absorbed at the PBX, so
        # the UAS sees exactly 1 INVITE with 1 PBX branch. Any second
        # INVITE — or any second branch — would prove a caller retransmit
        # was re-forwarded. (ACK/BYE mint fresh PBX branches by design;
        # only INVITEs are counted here.)
        msgs = parse_sipp_msg_log(logs_dir / "s4-call-uas-msg.log")
        invites = [m for m in msgs
                   if m.direction == "received" and m.is_request("INVITE")]
        branches = {b for m in invites
                    for b in via_branches(m, f"127.0.0.1:{PBX_PORT}")}
        assert len(invites) == 1, (
            f"s5-absorb: storm was re-forwarded, got {len(invites)} INVITEs")
        assert len(branches) == 1, (
            f"s5-absorb: want 1 PBX branch, got {sorted(branches)}")


def test_s6_cancel(pbx, logs_dir):
    """S6 via Python authed caller + sipp UAS: 401 handshake, CANCEL while
    proceeding → 200-to-CANCEL + 487, dialog torn down (bob re-registers
    first; same port as the dialog UAS)."""
    with expect_log_growth(logs_dir, "terminated (487)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "s6-cancel", "uas-cancel.xml",
                       UAS_PORT) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            try:
                call_id = f"pys6-{os.urandom(4).hex()}"
                dlg.handshake("bob", call_id, "pyalice1")
                dlg.cancel("bob", call_id, "pyalice1", 2)
            finally:
                dlg.close()
        assert uas.returncode == 0, "s6 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s6-cancel-uas-out.txt")


def test_callee_bye(pbx, logs_dir):
    """Mirror teardown via Python caller + sipp UAS: the callee hangs up
    (BYE from bob), the caller answers 200. Bob re-registers first, same
    port as the dialog UAS."""
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "callee-bye", "uas-answer-bye.xml",
                       UAS_PORT) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            try:
                call_id = f"pycb-{os.urandom(4).hex()}"
                to_tag, _ = dlg.invite("bob", call_id, "pyalice1")
                dlg.ack("bob", call_id, "pyalice1", to_tag, 2)
                dlg.wait_bye(200)
            finally:
                dlg.close()
        assert uas.returncode == 0, "callee-bye UAS exited non-zero"
        assert_sipp_ok(logs_dir / "callee-bye-uas-out.txt")


def test_callee_bye_rejected(pbx, logs_dir):
    """Rejected callee-BYE via Python caller: the caller's 403 routes back
    to the callee (post-teardown final, no cache pollution) and removes the
    dialog — proven by a probe BYE drawing 481."""
    with expect_log_growth(logs_dir, "torn down on BYE final"):
        register("bob", "bobpass", UAS_PORT)
        with sipp_uas(logs_dir, "callee-bye-reject", "uas-answer-reject.xml",
                       UAS_PORT) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            try:
                call_id = f"pycbr-{os.urandom(4).hex()}"
                to_tag, _ = dlg.invite("bob", call_id, "pyalice1")
                dlg.ack("bob", call_id, "pyalice1", to_tag, 2)
                dlg.wait_bye(403)
                dlg.bye("bob", call_id, 3, "pyalice1", to_tag,
                        branch="z9hG4bKpybye3", expect="SIP/2.0 481")
            finally:
                dlg.close()
        assert uas.returncode == 0, "callee-bye-reject UAS exited non-zero"
        assert_sipp_ok(logs_dir / "callee-bye-reject-uas-out.txt")


def test_s9_rtp_relay(pbx, logs_dir):
    """Live media loop: Python caller sends RTP to the relay port from the
    200's rewritten SDP; PBX relays to the echoing sipp UAS and back.
    Payloads must arrive byte-identical and ordered, both PBX directions
    logged. UAS media is pinned (flags) to its hardcoded SDP port; our
    socket binds the port our SDP advertises (exact-endpoint matching)."""
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        echo_flags = ("-rtp_echo", "-mi", "127.0.0.1",
                      "-min_rtp_port", "4000", "-max_rtp_port", "4000")
        with sipp_uas(logs_dir, "s9-rtp", "uas-answer.xml", UAS_PORT,
                       extra=echo_flags) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            media = MediaSocket(20000)
            try:
                call_id = f"pyrtp-{os.urandom(4).hex()}"
                _, ok = dlg.invite("bob", call_id, "pyalice1")
                relay_port = sdp_media_port(ok)
                assert relay_port and relay_port != 20000, (
                    f"200 SDP not anchored at relay: m={relay_port}")
                dlg.ack("bob", call_id, "pyalice1",
                        parse_to_tag(ok), 2)
                # Relay sockets open synchronously while the PBX processes
                # the ACK; media sent before that lands on an unbound port
                # and dies (no queue without a socket). Same pacing as S4.
                time.sleep(0.5)
                ssrc = 0x12345678
                sent = [rtp_packet(seq, seq * 160, ssrc, bytes([seq]) * 160)
                        for seq in range(1, 6)]
                for pkt in sent:
                    media.send(pkt, ("127.0.0.1", relay_port))
                for want in sent:
                    got = media.recv()
                    assert got == want, "relay mangled or reordered media"
                caller_logged = logs_dir / "pbx.log"
                text = caller_logged.read_text(errors="replace")
                assert "Forwarding from caller to callee" in text
                assert "Forwarding from callee to caller" in text
                dlg.bye("bob", call_id, 3, "pyalice1",
                        parse_to_tag(ok))
            finally:
                dlg.close()
                media.close()
        assert uas.returncode == 0, "s9 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s9-rtp-uas-out.txt")


def test_s10_reinvite(pbx, logs_dir):
    """Caller-initiated re-INVITE mid-dialog: new SDP offer (caller media
    moves 20000→20002) forwards with rewritten SDP, callee answers, media
    loop follows the new port, teardown clean. Bare (established legs ride
    the authenticated dialog)."""
    with expect_log_growth(logs_dir, "terminated (BYE)"):
        register("bob", "bobpass", UAS_PORT)
        echo_flags = ("-rtp_echo", "-mi", "127.0.0.1",
                      "-min_rtp_port", "4000", "-max_rtp_port", "4000")
        with sipp_uas(logs_dir, "s10-reinvite", "uas-reinvite.xml",
                       UAS_PORT, extra=echo_flags) as uas:
            time.sleep(1)
            dlg = Dialog("alice", "alicepass", UAC_PORT)
            media = MediaSocket(20000)
            try:
                call_id = f"pyri-{os.urandom(4).hex()}"
                to_tag, ok = dlg.invite("bob", call_id, "pyalice1")
                relay_caller = sdp_media_port(ok)
                assert relay_caller and relay_caller != 20000
                dlg.ack("bob", call_id, "pyalice1", to_tag, 2)
                time.sleep(0.5)
                # Baseline loop on the original ports.
                p0 = rtp_packet(1, 160, 0xAA, bytes([1]) * 160)
                media.send(p0, ("127.0.0.1", relay_caller))
                assert media.recv() == p0, "baseline media loop broken"
                media.close()
                # Renegotiate: caller media moves to 20002.
                media2 = MediaSocket(20002)
                try:
                    ok2 = dlg.reinvite("bob", call_id, "pyalice1", to_tag,
                                       20002)
                    assert sdp_media_port(ok2) == relay_caller, (
                        "re-INVITE must reuse the session relay ports")
                    dlg.ack("bob", call_id, "pyalice1", to_tag, 3)
                    time.sleep(0.5)
                    p1 = rtp_packet(2, 320, 0xAA, bytes([2]) * 160)
                    media2.send(p1, ("127.0.0.1", relay_caller))
                    got = media2.recv()
                    assert got == p1, "media did not follow the new port"
                finally:
                    media2.close()
                dlg.bye("bob", call_id, 4, "pyalice1", to_tag)
            finally:
                dlg.close()
        assert uas.returncode == 0, "s10 UAS exited non-zero"
        assert_sipp_ok(logs_dir / "s10-reinvite-uas-out.txt")

        # UAS saw exactly 2 INVITEs (initial + re-INVITE, CSeq 1/2 then 3).
        msgs = parse_sipp_msg_log(logs_dir / "s10-reinvite-uas-msg.log")
        invites = [m for m in msgs
                   if m.direction == "received" and m.is_request("INVITE")]
        assert len(invites) == 2, (
            f"s10: want 2 INVITEs at UAS, got {len(invites)}")


@pytest.mark.slow
def test_s8_timer_b(pbx, logs_dir):
    """S8 via Python caller: authed INVITE to the silent contact forwards,
    then nothing answers — linger until Timer B 408s (~32s) and tears down.
    The 408 is asserted on the wire and via the PBX log."""
    with expect_log_growth(logs_dir, "terminated (408"):
        register("silent", "silentpass", SILENT_PORT)
        register("alice", "alicepass", UAC_PORT)
        dlg = Dialog("alice", "alicepass", UAC_PORT, timeout=10)
        try:
            call_id = f"pys8-{os.urandom(4).hex()}"
            dlg.handshake("silent", call_id, "pyalice1")
            msg = dlg.linger_408(timeout=60)
            assert msg.startswith("SIP/2.0 408"), (
                f"want 408 after Timer B, got: {msg.split(chr(13))[0]}")
        finally:
            dlg.close()


# Must stay last: asserts the whole run left no error-level PBX log behind
# (retransmit/send failures, sweep failures and OOM paths all log here).
def test_no_errors(pbx, logs_dir):
    text = (logs_dir / "pbx.log").read_text(errors="replace")
    errors = [l for l in text.splitlines() if "] error(" in l]
    assert not errors, f"{len(errors)} error lines in pbx log: {errors[:5]}"
