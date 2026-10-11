# Roadmap

Deferred work. Each item states the prerequisite and how to verify it's
done. Last reviewed: 2026-10-11 (all items open).

## Protocol features

### Re-INVITE / hold-resume / session timers
Mid-dialog INVITEs are not renegotiated today (same-branch duplicates are
absorbed silently with no re-forward; see
`test_s4_call_and_s5_absorb`).
Codec changes, hold/resume, and `Session-Expires` refreshes need new
handling. Doing this touches `onInvite` (`src/pbx.zig:274`), the dialog
`invite_txn` slot (`src/call.zig:38`), and the RTP session media ports.
Verify with a new interop test: in-dialog re-INVITE with altered SDP →
200 with fresh anchored SDP → media flows to the new port. Approach:
add the test `xfail` first to characterize current behavior, flip on landing.

### INVITE-time authentication — done (verified unit + live)
`onInvite` challenges before lookup (`src/pbx.zig`, same
verify-then-401 shape as REGISTER, reusing the already method-agnostic
`verifyRequest` untouched, plus `sendUnauthorized` now public).
401 + `Authorization`, not 407 + `Proxy-*`: the PBX is registrar and
first hop in one box and every client (phones, pjsua) answers 401 to
INVITE; 407 stays a follow-up if the ecosystem demands it. Ordering
guarantees: loop protection first (S7 unchanged), duplicates absorb
before auth runs (consumed nonces can't re-challenge Timer-A
retransmits), unknown users 401 without reaching lookup (no
enumeration). Covered by 4 new unit tests (bare→401, wrong-pass→401,
unknown→401, duplicate-absorb) with `inviteHandshake` swapped across all
13 dialog call sites, and live by `interop/invite.py` (Python dialog
driver — sipp can't compute digests), which retired the 7 caller XMLs.
S3 is now authed-INVITE-to-unregistered → 404 + replay; S8 lingers 40s
post-handshake for the 408 (still 32.000s from the forwarded leg).

### Password config file — done (verified unit + live)
`Auth.loadUsersFile` (`src/auth.zig`) parses `user:password` lines (`#`
comments/blanks skipped, malformed warn-skipped) and seeds via `addUser`,
so HA1-only storage holds for file users. `main` takes an optional argv
path (else `./users.conf`, else warn + seeds); `Pbx.init` keeps its seeds
so all unit tests are untouched. `interop/users.conf` (same 3 users) is
passed explicitly by the pytest fixture — every interop run exercises the
file path. Rotation still needs a restart; INVITE-time auth remains the
next auth item.

## Verification upgrades

### Live RTP media — done (verified live, no pcap needed)
`test_s9_rtp_relay`: Python caller sends RTP to the relay port from its
SDP-advertised port; PBX relays to the echoing sipp UAS (`-rtp_echo`)
and back; payloads byte-identical and ordered, both PBX directions
logged. Two PBX fixes fell out, both with unit tests:
- Run loop slept to the next SIP deadline (up to 32s), starving `drain`
  during media-only periods (packets sat unread — seen as Recv-Q).
  Now capped at a 20ms quantum while any relay sockets are open
  (`rtp_poll_interval_ms`, `hasOpenRelays`); idle PBXs still sleep full
  deadlines, so S8 timing is unaffected.
- Forwards emanated from the SIP socket, so echoes returned to port 5060
  and died in the SIP parser. Forwards now emanate from the destination
  leg's relay socket (SIP-socket fallback preserves pre-ACK early media).
Calibrated flags (no new XML): `-mi 127.0.0.1` (endpoint match needs the
loopback source), `-min/-max_rtp_port 4000` (must equal the hardcoded
SDP — the PBX matches declared ports exactly).

### pjsua as second peer
A real-UA interop leg (in addition to sipp, not replacing it): genuine SDP
negotiation, real RTP, and ACK/CANCEL races from actual stack behavior
rather than scripted timers. Start with one registered-pjsua-receives-call
scenario before expanding.

### Zig-native UA harness (`zig build interop`)
Long-term: an in-house UA sharing `message.zig`/`parser.zig`, driving the
PBX in-process over real sockets. Would eventually subsume both the unit
e2e harness and the sipp suite. Deliberately deferred. Today it means
reimplementing the sipp behaviors we depend on (Timer-A retransmit drove
S5; strict step-matching catches our malformed output). Revisit once the
scenario count makes sipp-vs-PBX split-brain debugging dominate.

## Known code follow-ups

### Final-error leg-flip — done (verified live + unit)
The callee-BYE fix routed non-INVITE **2xx** responses via leg-flip
(shared `responseDest` helper). The final-error branch now has a
post-teardown arm for non-INVITE finals: a rejected callee-BYE routes to
the request sender, removes the dialog, and caches nothing (an
INVITE-response cache must never hold a BYE final). Covered by unit test
`e2e rejected callee-BYE routes to callee and removes dialog` (routing +
removal + cache-untouched asserts) and live `test_callee_bye_rejected`
(UAS gets the 403, probe BYE draws 481). INVITE finals arriving
post-teardown still drop — separate decision, still open.

## Ops bundle (all open)
Bind address / port CLI args, SIGTERM graceful shutdown, registrar
persistence across restarts. None started; none of it blocks loopback
interop.
