#!/usr/bin/env python3
"""Digest-auth REGISTER client for interop testing.

sipp 3.7.7 cannot answer 401 challenges from custom scenarios
([authentication] is gated behind internal dialog state, -au/-ap stay
inert), so registration goes through this helper instead:

  1. send bare REGISTER, require 401 with a nonce (proves auth enforced),
  2. answer with an MD5 Digest response, require 200 OK.

Usage: register.py [--qop] <user> <password> <local_port> [expires]
Exit 0 on 200 after a 401 challenge, 1 otherwise.
"""

import hashlib
import os
import re
import socket
import sys


def build_register(user, branch, call_id, cseq, contact_port, auth=None,
                   expires=3600, host="127.0.0.1", pbx_port=5060):
    lines = [
        f"REGISTER sip:{user}@{host}:{pbx_port} SIP/2.0",
        f"Via: SIP/2.0/UDP {host}:{contact_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}:{pbx_port}>;tag=pyreg",
        f"To: <sip:{user}@{host}:{pbx_port}>",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{user}@{host}:{contact_port}>",
    ]
    if auth is not None:
        lines.append(f"Authorization: {auth}")
    lines.append(f"Expires: {expires}")
    lines.append("Content-Length: 0")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse_www_auth(msg):
    m = re.search(r'WWW-Authenticate:\s*Digest\s+([^\r\n]+)', msg)
    if not m:
        return None
    params = {}
    for part in m.group(1).split(","):
        kv = part.strip().split("=", 1)
        if len(kv) == 2:
            params[kv[0].strip()] = kv[1].strip().strip('"')
    if "nonce" not in params:
        return None
    params.setdefault("realm", "pbx")
    return params


def digest_response(user, password, realm, nonce, method, uri, qop=False):
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop:
        cnonce = os.urandom(8).hex()
        nc = "00000001"
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{resp}", qop=auth, nc={nc}, cnonce="{cnonce}"')
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}"')


def recv_status(sock):
    data, _ = sock.recvfrom(4096)
    msg = data.decode(errors="replace")
    status = msg.split("\r\n", 1)[0]
    return status, msg


class RegisterError(Exception):
    """Raised when the REGISTER handshake fails (no 401, no 200, timeout)."""


def bare_register_status(user, port, timeout=5,
                         host="127.0.0.1", pbx_port=5060):
    """Send a bare (unauthenticated) REGISTER; return (status_line, message).

    Probes the challenge itself: an unknown user must still get 401 with a
    nonce (never 404 — no user enumeration). Raises RegisterError on timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(timeout)
    try:
        sock.sendto(build_register(user, f"z9hG4bKpybare-{os.urandom(4).hex()}",
                                   f"pybare-{user}", 1, port, None, 3600,
                                   host, pbx_port),
                     (host, pbx_port))
        try:
            return recv_status(sock)
        except TimeoutError:
            raise RegisterError("timed out waiting for 401 challenge")
    finally:
        sock.close()


def replay_authorization(user, password, port, timeout=5,
                         host="127.0.0.1", pbx_port=5060):
    """Full handshake, then resend the identical authed REGISTER bytes.

    Returns (first_status, second_status, second_msg). Single-use nonces
    mean the replay must fail: expect 200 the first time, 401 the second.
    Same branch, Call-ID, CSeq, nonce and nc — a true capture-replay, sent
    milliseconds apart so TTL expiry can't explain a rejection. Raises
    RegisterError on timeout or if the first leg doesn't 200.
    """
    uri = f"sip:{user}@{host}:{pbx_port}"
    call_id = f"pyreplay-{user}"
    tag = os.urandom(4).hex()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(timeout)
    try:
        sock.sendto(build_register(user, f"z9hG4bKpyreplay1-{tag}", call_id,
                                   1, port, None, 3600, host, pbx_port),
                     (host, pbx_port))
        try:
            status, msg = recv_status(sock)
        except TimeoutError:
            raise RegisterError("timed out waiting for 401 challenge")
        if not status.startswith("SIP/2.0 401"):
            raise RegisterError(f"expected 401 challenge, got: {status}")
        challenge = parse_www_auth(msg)
        if challenge is None:
            raise RegisterError("401 without parseable nonce")

        authed = build_register(
            user, f"z9hG4bKpyreplay2-{tag}", call_id, 2, port,
            digest_response(user, password, challenge["realm"],
                            challenge["nonce"], "REGISTER", uri, False),
            3600, host, pbx_port)
        try:
            sock.sendto(authed, (host, pbx_port))
            first, _ = recv_status(sock)
            sock.sendto(authed, (host, pbx_port))
            second, second_msg = recv_status(sock)
        except TimeoutError:
            raise RegisterError("timed out waiting for replay verdict")
        if not first.startswith("SIP/2.0 200"):
            raise RegisterError(f"expected 200 after auth, got: {first}")
        return first, second, second_msg
    finally:
        sock.close()


def register(user, password, port, expires=3600, use_qop=False, timeout=5,
             host="127.0.0.1", pbx_port=5060):
    """Bare-then-authed REGISTER handshake against the PBX.

    Returns on 200 OK after a 401 challenge; raises RegisterError otherwise.
    Branch values carry a random suffix so back-to-back registrations (plain,
    qop, negative) never alias an earlier transaction.
    """
    uri = f"sip:{user}@{host}:{pbx_port}"
    call_id = f"pyreg-{user}-qop" if use_qop else f"pyreg-{user}"
    tag = os.urandom(4).hex()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(timeout)

    try:
        sock.sendto(build_register(user, f"z9hG4bKpyreg1-{tag}", call_id, 1,
                                   port, None, expires, host, pbx_port),
                     (host, pbx_port))
        try:
            status, msg = recv_status(sock)
        except TimeoutError:
            raise RegisterError("timed out waiting for 401 challenge")
        if not status.startswith("SIP/2.0 401"):
            raise RegisterError(f"expected 401 challenge, got: {status}")
        challenge = parse_www_auth(msg)
        if challenge is None:
            raise RegisterError("401 without parseable nonce")

        auth = digest_response(user, password, challenge["realm"],
                               challenge["nonce"], "REGISTER", uri, use_qop)
        sock.sendto(build_register(user, f"z9hG4bKpyreg2-{tag}", call_id, 2,
                                   port, auth, expires, host, pbx_port),
                     (host, pbx_port))
        try:
            status, _ = recv_status(sock)
        except TimeoutError:
            raise RegisterError("timed out waiting for 200 OK")
        if not status.startswith("SIP/2.0 200"):
            raise RegisterError(f"expected 200 after auth, got: {status}")
    finally:
        sock.close()


def main():
    args = [a for a in sys.argv[1:] if a]
    use_qop = "--qop" in args
    args = [a for a in args if a != "--qop"]
    user, password, port = args[0], args[1], int(args[2])
    expires = int(args[3]) if len(args) > 3 else 3600

    try:
        register(user, password, port, expires, use_qop)
    except RegisterError as e:
        print(f"FAIL: {e}")
        return 1

    print(f"OK: {user} registered (401 challenged, 200 accepted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
