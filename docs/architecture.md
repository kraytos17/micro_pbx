# Architecture

How a datagram becomes a forwarded message. Anchors are current as of
2026-10-11.

## Event loop (`Pbx.run`, `src/pbx.zig:93`)
Blocking `receiveTimeout` → parse → dispatch → `handleTimeout` (`:186`).
The sleep duration is `min(server nextTimeout, dialog nextDialogTimeout,
registrar sweep due)` (see `docs/timers.md`), capped at 20ms
(`rtp_poll_interval_ms`) while any relay sockets are open: otherwise media sits
unread between SIP events. Timeout handling is
resend-before-sweep: retransmits go out before terminated entries are
reaped. Registrar sweep runs at most every 60s (`:108`,
`reg_sweep_interval_ms`, `src/pbx.zig:20`).

## REGISTER (`onRegister`, `src/pbx.zig:174` → `proxy.handleRegister`, `src/proxy.zig:205`)
1. `authenticator.verifyRequest`: any failure (unknown user, wrong
   password, bad/stale nonce) returns 401 via `sendUnauthorized`, with
   `stale=true` for expired nonces (`src/proxy.zig:213-218`). Auth
   failures are answers, never errors or log noise.
2. `Expires: 0` → `registrar.unregister(aor)` + 200 (`:223-226`).
3. Else `registrar.register(aor, from, expires, call_id, cseq)`; a
   `DuplicateCallId` retransmit still answers 200 per RFC 3261 (`:230-235`).

## INVITE (`onInvite`, `src/pbx.zig:318`)
1. Max-Forwards decrement; exhausted → 483, no state (`src/pbx.zig:332`).
2. Overload gate: unknown dialog + `calls.count() >= max_dialogs` (512)
   → 503 before any work (`:386-391`). 404s never reach here and never create
   dialog state.
3. Registrar lookup by dual-key AOR; miss → 404 (top Via echoed unchanged),
   cached under the client branch for retransmit replay (`:374-388`).
4. With SDP: `rtp_sessions.createSession` (`:439`), body rewritten toward
   the PBX relay port (`sdp.rewriteSdp`, `:440`), forwarded via
   `proxy.handleInvite` (100 to caller; branch minted; sent to contact).
5. Dialog ensured (`Dialog{call, invite_txn, arena}`, `src/call.zig:45`)
   with the forwarded-INVITE client transaction for Timer A/B.
6. Same-branch duplicates: retransmission detected → absorbed silently:
   no re-forward, no new state, no re-challenge (consumed nonces stay
   consumed).

## Re-INVITE (`forwardReinvite`, established + higher CSeq only)
Pre-answer retries, same-branch dupes, and stale CSeq all absorb exactly
as before — only `established` + `cseq > invite_cseq` renegotiates, and
it skips authentication (rides the dialog, like BYE). The forward reuses
the session (caller leg updated in place via `setCaller`; ports/sockets
stay), mints a fresh PBX branch without a 100, and tracks the re-leg in
the free `invite_txn` slot. `invite_branch` keeps the ORIGINAL leg (Timer-B
identity); `invite_cseq` advances; `reinvite_via/from/to` feed re-leg 408
rendering. Answers land in the established-state 2xx arm (forward +
`setCallee`, no state flip, transaction completed so no phantom 408);
an unanswered re-leg 408s without teardown (branch compared, dialog kept).
Re-ACKs only forward — relay sockets open once (`== null` guard), or every
re-ACK would rebind held ports into the error log.

## Responses (`handleResponse`, `src/pbx.zig:725`)
1. CANCEL responses terminate here (caller was already answered, `:733`).
2. `dest_addr` defaults to the caller (`:740`): correct for every
   INVITE answer (100 excepted: the caller already got its own Trying;
   180/200 forward and record `callee_resp_addr`; 2xx ends the client
   transaction with no Timer D).
3. **Non-INVITE 2xx uses leg-flip** (`responseDest`, `src/pbx.zig:665`): response sender
   is the caller → route to the callee contact, else to the caller. This
   is the callee-BYE fix. The caller-ward default bounced BYE-200s to
   their sender. A terminating dialog is removed when its BYE is answered
   (`:794-798`).
4. 487 in `canceling` state terminates, forwards, caches under both
   branches, and completes the INVITE transaction. Other finals terminate
   and cache similarly. No dialog → forward to `from` (covers stray
   traffic without crashing).
5. Every forward strips the top Via (`stripTopVia`, `src/proxy.zig:100`),
   which understands comma-folded multi-Via (`:111-128`): drop only the
   first value.

## BYE (`onBye`, `src/pbx.zig:572`) and CANCEL (`onCancel`, `:625`)
- BYE routes by the same leg-flip (`:582-587`), terminates immediately,
  kills the INVITE transaction (stops Timer A), and drops the RTP session.
  But the dialog entry survives until the BYE-200 arrives so the response
  relays to the right side instead of bouncing (`:596-598`). No dialog →
  481, never a crash.
- CANCEL in `proceeding`/`ringing` → `canceling`, 200 to the canceller,
  forwarded to the callee by the original INVITE branch; missing callee → 481.

## Ownership (who frees what)
| Resource | Owner | Released by |
|---|---|---|
| Dialog state + txn buffers | per-dialog arena (`src/call.zig:98-101`) | arena destroy at `removeCall`; no per-field frees exist |
| RTP relay sockets | `Sessions`, opened on ACK | `removeSession` / `deinit`, exactly once (`src/rtp.zig:70-71,92,183`) |
| Nonce table copies | `Auth.nonces` | expiry sweep (`src/auth.zig:258`) |

| Generated branches | caller stack buffer (`generateBranch` into `[32]u8`) | borrowed synchronously; arena dupes what persists |

Measured (P5 probe, release binary, 320 live dialogs): **≈2.6 kB/dialog**
marginal RSS (linear fit, intercept ≈1.6 MB), VmHWM monotonic, zero 408s
inside the window. Well under the 8KB first-bucket theory — small allocs
share bucket segments — and the 512-dialog cap bounds the worst case near
~1.3 MB. Verdict: arenas stay; no slab.

## Borrow discipline
`Retransmission` and `TickEvent` payloads borrow map memory
(`src/sip/transaction.zig:89-104`). Borrowed payloads impose one rule: act
(send) before any mutation or removal. Timer-driven dialog expiries are
collect-then-act: mutating the table while iterating it is invalid.
`dlg_ptr` dies at `ensureDialog` (possible rehash), so re-fetch the handle
after any call that may insert.
