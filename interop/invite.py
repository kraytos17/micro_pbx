"""Digest-auth INVITE dialog driver for interop testing.

sipp cannot compute Digest responses in custom scenarios ([authentication]
stays inert outside its built-in flows), so dialog callers go through this
helper instead — mirroring the register.py split for REGISTER:

  1. send bare INVITE, require 401 with a nonce (proves INVITE auth enforced),
  2. answer with an MD5 Digest response (fresh branch, CSeq 2), require 100,
  3. drive the dialog per the requested teardown mode.

Teardown modes (teardown=):
  "caller-bye"  — ACK, pause, BYE, expect 200 (S4 shape).
  "cancel"      — after 180, CANCEL, expect 200-to-CANCEL + 487 (S6 shape).
  "wait-bye"    — ACK, wait for inbound BYE, answer `bye_answer` (200/403).
  "linger"      — handshake then go quiet (Timer-B 408 measurement).

Strict like sipp: unexpected messages abort the dialog (they are
regression tripwires, not noise). Callers must use distinct local ports
per concurrent dialog; sequential tests share UAC_PORT.
"""

import socket
import time

from register import digest_response, parse_www_auth


def build_invite(user, callee, branch, call_id, cseq, contact_port, from_tag,
                 to_tag=None, auth=None, sdp=True, sdp_port=20000,
                 host="127.0.0.1", pbx_port=5060):
    to = f"<sip:{callee}@{host}:{pbx_port}>" + (f";tag={to_tag}" if to_tag else "")
    lines = [
        f"INVITE sip:{callee}@{host}:{pbx_port} SIP/2.0",
        f"Via: SIP/2.0/UDP {host}:{contact_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}:{pbx_port}>;tag={from_tag}",
        f"To: {to}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} INVITE",
        f"Contact: <sip:{user}@{host}:{contact_port}>",
    ]
    if auth is not None:
        lines.append(f"Authorization: {auth}")
    body = ""
    if sdp:
        body = (f"\r\nv=0\r\no=caller 12345 67890 IN IP4 127.0.0.1\r\n"
                f"s=pytest\r\nc=IN IP4 127.0.0.1\r\nm=audio {sdp_port} RTP/AVP 0\r\n")
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def build_ack(user, callee, branch, call_id, contact_port, from_tag, to_tag,
              invite_cseq, host="127.0.0.1", pbx_port=5060):
    # ACK echoes the ANSWERED invite's CSeq (2 after the 401 dance), not 1:
    # sipp aborts the call on mismatch ("ACK CSeq value does NOT match").
    lines = [
        f"ACK sip:{callee}@{host}:{pbx_port} SIP/2.0",
        f"Via: SIP/2.0/UDP {host}:{contact_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}:{pbx_port}>;tag={from_tag}",
        f"To: <sip:{callee}@{host}:{pbx_port}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {invite_cseq} ACK",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def build_bye(user, callee, branch, call_id, cseq, contact_port, from_tag,
              to_tag, host="127.0.0.1", pbx_port=5060):
    lines = [
        f"BYE sip:{callee}@{host}:{pbx_port} SIP/2.0",
        f"Via: SIP/2.0/UDP {host}:{contact_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}:{pbx_port}>;tag={from_tag}",
        f"To: <sip:{callee}@{host}:{pbx_port}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} BYE",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def build_cancel(user, callee, branch, call_id, contact_port, from_tag,
                 invite_cseq, host="127.0.0.1", pbx_port=5060):
    # CANCEL echoes the INVITE's CSeq (the one being cancelled).
    lines = [
        f"CANCEL sip:{callee}@{host}:{pbx_port} SIP/2.0",
        f"Via: SIP/2.0/UDP {host}:{contact_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}:{pbx_port}>;tag={from_tag}",
        f"To: <sip:{callee}@{host}:{pbx_port}>",
        f"Call-ID: {call_id}",
        f"CSeq: {invite_cseq} CANCEL",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def build_response_for(request_text, code, reason, to_tag=None):
    """Minimal final response echoing Via/From/Call-ID/CSeq of a request."""
    headers = {}
    for line in request_text.replace("\r\n", "\n").split("\n")[1:]:
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    to = headers.get("to", ["<sip:unknown>"])[0]
    if to_tag and "tag=" not in to:
        to += f";tag={to_tag}"
    out = [f"SIP/2.0 {code} {reason}"]
    for v in headers.get("via", []):
        out.append(f"Via: {v}")
    out.append(f"From: {headers.get('from', ['<sip:unknown>'])[0]}")
    out.append(f"To: {to}")
    out.append(f"Call-ID: {headers.get('call-id', ['x'])[0]}")
    out.append(f"CSeq: {headers.get('cseq', ['1 BYE'])[0]}")
    out.append("Content-Length: 0")
    return ("\r\n".join(out) + "\r\n\r\n").encode()


def parse_to_tag(msg):
    import re
    m = re.search(r"(?im)^To:.*tag=([^\s;,]+)", msg)
    return m.group(1) if m else None


class InviteError(Exception):
    """Raised when the INVITE handshake or dialog drive fails."""


class Dialog:
    """One UDP socket driving a single authenticated dialog."""

    def __init__(self, user, password, port, host="127.0.0.1", pbx_port=5060,
                 timeout=8):
        self.user = user
        self.password = password
        self.port = port
        self.host = host
        self.pbx_port = pbx_port
        self.last_invite = None  # authed INVITE bytes, for Timer-A-style resends
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(timeout)

    def close(self):
        self.sock.close()

    def _send(self, data):
        self.sock.sendto(data, (self.host, self.pbx_port))

    def _recv(self):
        try:
            data, _ = self.sock.recvfrom(65536)
        except TimeoutError:
            raise InviteError("timed out waiting for message")
        return data.decode(errors="replace")

    def _expect(self, prefix, what):
        msg = self._recv()
        status = msg.split("\r\n", 1)[0]
        if not status.startswith(prefix):
            raise InviteError(f"expected {what}, got: {status}")
        return msg

    def handshake(self, callee, call_id, from_tag, branch="z9hG4bKpyinv1"):
        """Bare→401→authed handshake through the PBX's own 100.

        One bare leg, one authed leg, no retransmits. Returns after the
        forwarded leg's 100 arrives. Later phases are strict (see
        wait_bye): unexpected messages abort.
        """
        uri = f"sip:{callee}@{self.host}:{self.pbx_port}"
        self._send(build_invite(self.user, callee, branch, call_id, 1,
                                self.port, from_tag, host=self.host,
                                pbx_port=self.pbx_port))
        msg = self._recv()
        status = msg.split("\r\n", 1)[0]
        if not status.startswith("SIP/2.0 401"):
            raise InviteError(f"expected 401 challenge, got: {status}")
        challenge = parse_www_auth(msg)
        if challenge is None:
            raise InviteError("401 without parseable nonce")
        auth = digest_response(self.user, self.password,
                               challenge["realm"], challenge["nonce"],
                               "INVITE", uri, False)
        authed = build_invite(self.user, callee, branch + "-auth", call_id,
                               2, self.port, from_tag, None, auth, True,
                               20000, self.host, self.pbx_port)
        self._send(authed)
        self.last_invite = authed
        self._expect("SIP/2.0 100", "100 Trying")

    def invite(self, callee, call_id, from_tag, branch="z9hG4bKpyinv1"):
        """Full handshake through answer. Returns (peer_to_tag, ok_message).

        180 is optional (UAS may answer 200 directly).
        """
        self.handshake(callee, call_id, from_tag, branch)
        msg = self._recv()
        status = msg.split("\r\n", 1)[0]
        if status.startswith("SIP/2.0 180"):
            msg = self._expect("SIP/2.0 200", "200 OK")
        elif not status.startswith("SIP/2.0 200"):
            raise InviteError(f"expected 180/200, got: {status}")
        return parse_to_tag(msg), msg

    def call_expect(self, callee, call_id, from_tag, expect,
                  branch="z9hG4bKpyce"):
        """Handshake, then return the first post-auth message, which must
        start with expect (e.g. a 404 for an unregistered callee — no 100
        precedes direct errors). Stores the authed bytes for resend_last().
        """
        uri = f"sip:{callee}@{self.host}:{self.pbx_port}"
        self._send(build_invite(self.user, callee, branch, call_id, 1,
                                self.port, from_tag, None, None, False,
                                20000, self.host, self.pbx_port))
        msg = self._recv()
        status = msg.split("\r\n", 1)[0]
        if not status.startswith("SIP/2.0 401"):
            raise InviteError(f"expected 401 challenge, got: {status}")
        challenge = parse_www_auth(msg)
        if challenge is None:
            raise InviteError("401 without parseable nonce")
        auth = digest_response(self.user, self.password,
                               challenge["realm"], challenge["nonce"],
                               "INVITE", uri, False)
        authed = build_invite(self.user, callee, branch + "-auth", call_id,
                               2, self.port, from_tag, None, auth, False,
                               20000, self.host, self.pbx_port)
        self._send(authed)
        self.last_invite = authed
        msg = self._recv()
        status = msg.split("\r\n", 1)[0]
        if not status.startswith(expect):
            raise InviteError(f"expected {expect}, got: {status}")
        return msg

    def cancel(self, callee, call_id, from_tag, invite_cseq,
               branch="z9hG4bKpycancel"):
        """CANCEL an early dialog: expect 200-to-CANCEL then 487-to-INVITE."""
        self._send(build_cancel(self.user, callee, branch, call_id,
                                self.port, from_tag, invite_cseq, self.host,
                                self.pbx_port))
        self._expect("SIP/2.0 200", "200 for CANCEL")
        self._expect("SIP/2.0 487", "487 for INVITE")

    def linger_408(self, timeout=60):
        """Wait out a Timer-B expiry for an unanswered forward. Returns the
        408 text; ignores anything else (stray 100s)."""
        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                raise InviteError("timed out waiting for 408")
            try:
                msg = self._recv()
            except InviteError:
                continue
            if msg.split("\r\n", 1)[0].startswith("SIP/2.0 408"):
                return msg
            continue

    def resend_last(self):
        """Resend the authed INVITE byte-identical (Timer-A-style duplicate).

        The PBX must absorb it: no re-forward, no re-challenge (consumed
        nonce), dialog untouched.
        """
        if self.last_invite is None:
            raise InviteError("no INVITE sent yet")
        self._send(self.last_invite)

    def reinvite(self, callee, call_id, from_tag, to_tag, new_sdp_port,
                 invite_cseq=3, branch="z9hG4bKpyreinv"):
        """Bare in-dialog re-INVITE with a new SDP offer. Established legs
        ride the authenticated dialog, so no credentials are attached.
        Returns the 200 message."""
        self._send(build_invite(self.user, callee, branch, call_id,
                                invite_cseq, self.port, from_tag, to_tag,
                                None, True, new_sdp_port, self.host,
                                self.pbx_port))
        return self._expect("SIP/2.0 200", "200 for re-INVITE")

    def ack(self, callee, call_id, from_tag, to_tag, invite_cseq,
            branch="z9hG4bKpyack"):
        self._send(build_ack(self.user, callee, branch, call_id, self.port,
                             from_tag, to_tag, invite_cseq, self.host,
                             self.pbx_port))

    def bye(self, callee, call_id, cseq, from_tag, to_tag,
            branch="z9hG4bKpybye", expect="SIP/2.0 200"):
        self._send(build_bye(self.user, callee, branch, call_id, cseq,
                             self.port, from_tag, to_tag, self.host,
                             self.pbx_port))
        self._expect(expect, f"{expect} for BYE")

    def wait_bye(self, answer_code, answer_tag="pybye"):
        """Wait for an inbound BYE, answer with answer_code. Returns the
        raw BYE text. Strict like sipp: anything unexpected aborts the
        dialog (these are regression tripwires — a bounced duplicate here
        once caught a real PBX routing bug). Timeout comes from the socket."""
        msg = self._recv()
        start = msg.split("\r\n", 1)[0]
        if not start.startswith("BYE "):
            detail = " | ".join(
                line for line in msg.replace("\r\n", "\n").split("\n")
                if line[:5].lower() in ("call-", "cseq ", "via: "))
            raise InviteError(f"expected inbound BYE, got: {start} [{detail}]")
        self._send(build_response_for(msg, answer_code,
                                      "OK" if answer_code == 200 else "Forbidden",
                                      answer_tag))
        return msg


def rtp_packet(seq, timestamp, ssrc, payload):
    """Minimal RTPv2 packet (PT 0 PCMU, no extensions/CSRC), matching what
    Header.parse accepts. The relay forwards bytes intact; seq/ts/ssrc let
    the test prove ordering and preservation end to end."""
    import struct
    header = struct.pack(">BBHII", 0x80, 0x00, seq, timestamp, ssrc)
    return header + payload


def sdp_media_port(sdp_msg, default=None):
    """First m=audio port in a SIP message (the PBX-rewritten relay port)."""
    import re
    m = re.search(r"(?im)^m=audio (\d+)", sdp_msg)
    return int(m.group(1)) if m else default


class MediaSocket:
    """One UDP socket bound to the SDP-advertised media port.

    Binding matters, not just sending: the relay matches the exact source
    endpoint (IP, port) recorded from SDP, so media must originate from the
    advertised port or it drops.
    """

    def __init__(self, port, host="127.0.0.1", timeout=5):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(timeout)

    def close(self):
        self.sock.close()

    def send(self, data, addr):
        self.sock.sendto(data, addr)

    def recv(self):
        try:
            data, _ = self.sock.recvfrom(65536)
        except TimeoutError:
            raise InviteError("timed out waiting for media")
        return data


def bare_invite_status(user, callee, port, timeout=5, host="127.0.0.1",
                       pbx_port=5060):
    """Send a bare INVITE; return (status_line, message). Probes whether
    INVITE auth is enforced (expect 401, never 404/forward)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(timeout)
    try:
        sock.sendto(build_invite(user, callee, "z9hG4bKpybareinv",
                                 f"pybareinv-{user}", 1, port, "pytag",
                                 None, None, False, 20000, host, pbx_port),
                     (host, pbx_port))
        try:
            data, _ = sock.recvfrom(4096)
        except TimeoutError:
            raise InviteError("timed out waiting for 401 challenge")
        msg = data.decode(errors="replace")
        return msg.split("\r\n", 1)[0], msg
    finally:
        sock.close()
