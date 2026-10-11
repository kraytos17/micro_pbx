# Transaction Timers

RFC 3261 §17 timers as implemented in `src/sip/transaction.zig`, with the
two decisions that differ from a naive reading of the RFC. Constants at
`src/sip/transaction.zig:17-26`.

## Values
| Timer | Value | Meaning |
|---|---|---|
| T1 (`t1_ms`) | 500ms | RTT estimate; first retransmit delay |
| T2 (`t2_ms`) | 4s | backoff cap: each retransmit doubles, clamped (`tickOne`, `:157`) |
| Timer B (`timer_b_ms`) | 32s | INVITE client-transaction timeout → 408 + teardown |
| Timer F (`timer_f_ms`) | 32s | non-INVITE client-transaction timeout |
| Timer D (`timer_d_ms`) | 32s | absorb window after a completed dialog transaction |

## Decision 1: B/F fire on elapsed time, not retransmit count
The RFC's "64·T1" is a duration. Counting 64 retransmits instead would
interact with capped backoff (500ms→1s→2s→4s→4s…) to stretch expiry into
minutes. Each transaction records `created_at_ms` (`:82-84`), and `tickOne`
(`:139`) terminates on `now - created >= 64·T1` regardless of schedule:
even when the next retransmit sits *past* the deadline.
Both halves are unit-tested: fresh transactions retransmit while B is far
off; backdated ones expire (`tick terminates invite transaction after
Timer B`, `:448`).

## Decision 2: the event loop sleeps to the lapse, not just the next fire
With capped backoff the next retransmit can sit up to T2 (4s) past a 32s
deadline. `nextTimeout` (`:248`) therefore returns
`min(next retransmit fire, next B/F/D lapse)`. The lapse term covers both
the server layer and dialog transactions (`nextDialogTimeout`,
`src/call.zig:114`). The run loop (`Pbx.run`, `src/pbx.zig:83`) sleeps on
that minimum via `receiveTimeout`, then `handleTimeout` (`:171`)
resends-before-sweeping. Live proof: S8's 408 fires at 32.000s after the
INVITE (measured in interop logs), not 32–36s.

## Lifecycle notes
- 408 path: `onInviteTimeout` (`src/pbx.zig:224`) 408s the caller and tears
  down the dialog, verified live (`test_s8_timer_b`) and in unit tests
  (`e2e Timer B expiry sends 408`, `src/pbx.zig:1167`).
- 2xx ends the INVITE client transaction with no Timer D (RFC 3261);
  486 completes it and Timer D sweeps it (unit-tested, `src/pbx.zig:1231`).
- Duplicate INVITEs (same branch) are absorbed with a second 100 and never
  re-forwarded. The S5 branch-cardinality assert proves it
  (`test_s4_call_and_s5_absorb`).
- Non-INVITE finals are cached under the client branch (404 replay, S3);
  error caching degrades to warn-and-continue under table pressure rather
  than failing the original response.
- Table pressure: 512 transactions (`max_transactions`, `:26`) then
  `TransactionTableFull`; 512 dialogs (`max_dialogs`, `src/call.zig:63`)
  then 503 before any work (`src/pbx.zig:340`). 404s bypass the dialog
  gate (they create no state by design).
