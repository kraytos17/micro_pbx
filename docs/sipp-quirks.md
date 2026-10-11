# SIPp 3.7.7 Quirks Catalog

Every entry below was proven with a minimal stub scenario before the suite
was built around it. Last verified: 2026-10-11 against `SIPp v3.7.7-TLS-SCTP-PCAP-SHA256`.

## 1. Responses correlate only for keyword-generated Call-IDs
An incoming dialog arrives under the *caller's* foreign Call-ID, so a
single scenario run cannot both REGISTER (own Call-ID) and answer a dialog.
Consequence: registration and dialog are always two processes:
`register.py` first (foreground, deterministic order), then the dialog UAS
on the same port. The deleted `uas-reg.xml`/`uac-reg-silent.xml` were
attempts at single-process registration; they can never work, don't
resurrect them.

## 2. Completed-transaction responses are discarded
Once sipp's own INVITE transaction completes (first 404), a replayed second
404 is silently dropped. The scenario cannot assert it. Consequence: S3's
replay half is asserted via the PBX log (`retransmission detected`
growth), never via sipp matching. Rule: **any PBX retransmit/cache replay
must be asserted PBX-log-side** (`expect_log_growth`), with the sipp side
ending in a bare `<pause/>`.

## 3. Multi-Via is comma-folded on send
sipp emits one Via line per hop inbound, but folds `Via: A, B` onto one
line outbound. Consequence: branch-cardinality checks
(S5) must comma-split Via values before extracting `branch=`; see
`via_branches()` in `interop/sipassert.py`, which handles both forms. The
old `cut -d, -f1` pipeline got this wrong twice (stray `\r`, folded lines).

## 4. `[authentication]` never answers 401s in custom scenarios
`-au`/`-ap` stay inert outside sipp's built-in UAC flows (stub-proven).
Consequence: **all** REGISTER steps go through `interop/register.py`
(bare→401→authed→200, plain and `qop=auth`), never through sipp XML.

## 5. Timer A ignores 100s
A 100 Trying does not stop sipp caller retransmission the way strict
RFC 3261 would suggest; caller-side duplicates are driven explicitly
(S5's manual same-branch storm in `uac-alice-call.xml`) instead of relying
on timers.

## 6. Abort-BYE exits 0
A scenario that aborts (e.g. unexpected message during a pause) still
sends a BYE for the dead call and **exits 0**. Consequence: the suite gates
on sipp's `Successful call` (≥1) / `Failed call` (== 0) counters via
`assert_sipp_ok()`, never on process exit status. Both UAC and UAS legs get
gated. `wait()` + returncode alone once passed a dead call in development.

## 7. Unexpected messages abort, even in `<pause/>`
Any datagram arriving during a pause that matches no pending `recv` aborts
the call. Two incidents, opposite fixes. Learn both:
- **Keep trailing pauses as tripwires.** `uac-alice-callee-bye.xml` ends
  `send 200 → pause → end`. That pause caught a real PBX bug (BYE-200
  bounced back to its sender, `src/pbx.zig:591` fix). S4's UAC ends at
  `recv` with no pause, which is why the same bug was invisible there.
- **Never pause before a `recv` you can arm immediately.** A 500ms UAC
  pause before `recv BYE` tied with the UAS's 500ms post-ACK pause; when the
  BYE won by milliseconds sipp aborted on "unexpected BYE" (~30% flake).
  `recv` arms right after the ACK now, strictly before the BYE can exist
  (the UAS only sends it after receiving that ACK). The ordering is
  deterministic by construction; no timing margin needed.

## 8. `<send>` without `retrans` does not retransmit
Only sends with explicit `retrans="500"` (the INVITE storms) retransmit.
Bare `<send>` fires once. Don't add `retrans` to final-message sends: with
no subsequent `recv`, nothing cancels the timer and the re-send hits a
torn-down dialog (481 noise in the PBX log).
