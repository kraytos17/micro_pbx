# Architecture

How a datagram becomes a forwarded message. Anchors are current as of
2026-10-11.

## Event loop (`Pbx.run`, `src/pbx.zig:83`)
Blocking `receiveTimeout` → parse → dispatch → `handleTimeout` (`:171`).
The sleep duration is `min(server nextTimeout, dialog nextDialogTimeout,
registrar sweep due)` (see `docs/timers.md`), capped at 20ms
(`rtp_poll_interval_ms`) while any relay sockets are open: otherwise media sits
unread between SIP events. Timeout handling is
resend-before-sweep: retransmits go out before terminated entries are
reaped. Registrar sweep runs at most every 60s (`:98`,
`reg_sweep_interval_ms`, `src/pbx.zig:20`).

## REGISTER (`onRegister`, `src/pbx.zig:159` → `proxy.handleRegister`, `src/proxy.zig:203`)
1. `authenticator.verifyRequest`: any failure (unknown user, wrong
   password, bad/stale nonce) returns 401 via `sendUnauthorized`, with
   `stale=true` for expired nonces (`src/proxy.zig:212-218`). Auth
   failures are answers, never errors or log noise.
2. `Expires: 0` → `registrar.unregister(aor)` + 200 (`:222-226`).
3. Else `registrar.register(aor, from, expires, call_id, cseq)`; a
   `DuplicateCallId` retransmit still answers 200 per RFC 3261 (`:230-235`).

## INVITE (`onInvite`, `src/pbx.zig:274`)
1. Max-Forwards decrement; exhausted → 483, no state (`src/pbx.zig:288`).
2. Overload gate: unknown dialog + `calls.count() >= max_dialogs` (512)
   → 503 before any work (`:340`). 404s never reach here and never create
   dialog state.
3. Registrar lookup by dual-key AOR; miss → 404 (top Via echoed unchanged),
   cached under the client branch for retransmit replay (`:318-333`).
4. With SDP: `rtp_sessions.createSession` (`:352`), body rewritten toward
   the PBX relay port (`sdp.rewriteSdp`, `:353`), forwarded via
   `proxy.handleInvite` (100 to caller; branch minted; sent to contact).
5. Dialog ensured (`Dialog{call, invite_txn, arena}`, `src/call.zig:38`)
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

## Responses (`handleResponse`, `src/pbx.zig:522`)
1. CANCEL responses terminate here (caller was already answered, `:532`).
2. `dest_addr` defaults to the caller (`:537`): correct for every
   INVITE answer (100 excepted: the caller already got its own Trying;
   180/200 forward and record `callee_resp_addr`; 2xx ends the client
   transaction with no Timer D).
3. **Non-INVITE 2xx uses leg-flip** (`peer_addr`, `:591`): response sender
   is the caller → route to the callee contact, else to the caller. This
   is the callee-BYE fix. The caller-ward default bounced BYE-200s to
   their sender. A terminating dialog is removed when its BYE is answered
   (`:603-606`).
4. 487 in `canceling` state terminates, forwards, caches under both
   branches, and completes the INVITE transaction. Other finals terminate
   and cache similarly. No dialog → forward to `from` (covers stray
   traffic without crashing).
5. Every forward strips the top Via (`stripTopVia`, `src/proxy.zig:100`),
   which understands comma-folded multi-Via (`:111-128`): drop only the
   first value.

## BYE (`onBye`, `src/pbx.zig:433`) and CANCEL (`onCancel`, `:487`)
- BYE routes by the same leg-flip (`:444-448`), terminates immediately,
  kills the INVITE transaction (stops Timer A), and drops the RTP session.
  But the dialog entry survives until the BYE-200 arrives so the response
  relays to the right side instead of bouncing (`:458-461`). No dialog →
  481, never a crash.
- CANCEL in `proceeding`/`ringing` → `canceling`, 200 to the canceller,
  forwarded to the callee by the original INVITE branch; missing callee → 481.

## Ownership (who frees what)
| Resource | Owner | Released by |
|---|---|---|
| Dialog state + txn buffers | per-dialog arena (`src/call.zig:91-94`) | arena destroy at `removeCall`; no per-field frees exist |
| RTP relay sockets | `Sessions`, opened on ACK | `removeSession` / `deinit`, exactly once (`src/rtp.zig:70-71,92,155`) |
| Nonce table copies | `Auth.nonces` | expiry sweep (`src/auth.zig:226`) |
| Generated branches | caller (`generateBranch`) | `defer free` at each site (e.g. `onBye`, `:439-440`) |

## Borrow discipline
`Retransmission` and `TickEvent` payloads borrow map memory
(`src/sip/transaction.zig:87-102`). Borrowed payloads impose one rule: act
(send) before any mutation or removal. Timer-driven dialog expiries are
collect-then-act: mutating the table while iterating it is invalid.
`dlg_ptr` dies at `ensureDialog` (possible rehash), so re-fetch the handle
after any call that may insert.
