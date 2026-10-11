# Roadmap

Deferred work. Each item states the prerequisite and how to verify it's
done. Last reviewed: 2026-10-11 (all items open).

## Protocol features

### Re-INVITE / hold-resume / session timers
Mid-dialog INVITEs are not renegotiated today (same-branch duplicates are
absorbed with a second 100 and no re-forward; see
`test_s4_call_and_s5_absorb`).
Codec changes, hold/resume, and `Session-Expires` refreshes need new
handling. Doing this touches `onInvite` (`src/pbx.zig:274`), the dialog
`invite_txn` slot (`src/call.zig:38`), and the RTP session media ports.
Verify with a new interop test: in-dialog re-INVITE with altered SDP →
200 with fresh anchored SDP → media flows to the new port. Approach:
add the test `xfail` first to characterize current behavior, flip on landing.

### INVITE-time authentication
Only REGISTER is challenged today (`proxy.handleRegister`,
`src/proxy.zig:203`). INVITEs from unregistered endpoints are served
(404/forward) without auth. Requires the password config file first (below),
then a `407 Proxy Authentication Required` path mirroring the 401 flow plus
an interop test (bare INVITE → 407 → authed INVITE → forward). Until then,
the PBX trusts the loopback, which is acceptable while it only serves
loopback. See `docs/auth-security-model.md`.

### Password config file
Users are seeded in `Pbx.init` (`src/pbx.zig:58-60`: alice/bob/silent).
Move to a config file (path TBD, likely alongside the future bind/port
CLI args). Must preserve the HA1-only storage invariant: parse
`user:password` at startup, store `addUser` verifiers, never retain the
passwords. Unit test: file reload yields identical verifiers to `addUser`.

## Verification upgrades

### Live RTP media (`play_pcap`)
RTP relay is proven today by unit loopback tests (`src/rtp.zig`, 11 tests)
and by SDP anchoring assertions in sipp message logs — but no RTP packet
has ever crossed the live PBX. Plan: UAC `play_pcap_audio` → PBX relay →
UAS `rtp_echo`, assert relayed packets arrive rewritten. Blockers: a pcap
fixture (generate a minimal one in-test or vendor it) and SDP-port juggling
against the PBX's anchoring. Mark `slow`.

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

### Final-error leg-flip (`src/pbx.zig:628`)
The callee-BYE fix routed non-INVITE **2xx** responses via leg-flip
(`peer_addr`, `src/pbx.zig:591`). The final-error branch just below still
routes non-INVITE finals (e.g. a rejected callee-BYE) caller-ward, and
caches them as INVITE responses (`storeInviteResponse`,
`cacheErrorResponse`), both suspect for non-INVITE methods. With no live
coverage hitting that path, it stays untouched. Fix together with a live
test (callee-BYE rejected 4xx → routed to callee, dialog torn down, no
cache pollution).

## Ops bundle (all open)
Bind address / port CLI args, SIGTERM graceful shutdown, registrar
persistence across restarts. None started; none of it blocks loopback
interop.
