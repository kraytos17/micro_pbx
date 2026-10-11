# SIPp 3.7.7 Quirks Catalog

Every entry below was proven with a minimal stub scenario before the suite
was built around it. Last verified: 2026-10-11 against `SIPp v3.7.7-TLS-SCTP-PCAP-SHA256`.

## 1. Responses correlate only for keyword-generated Call-IDs
An incoming dialog arrives under the *caller's* foreign Call-ID, so a
single sipp run cannot both REGISTER (own Call-ID) and answer a dialog —
and since INVITE authentication landed, it cannot drive a dialog caller
either (see §4). Consequence: sipp keeps only the callee leg and S7;
registration goes through `register.py`, dialog callers through
`invite.py`'s `Dialog` driver. The deleted `uas-reg.xml`/`uac-reg-silent.xml`
(and the 7 retired caller XMLs) were attempts at single-process sipp flows;
they can never work, don't resurrect them.

## 2. Cache replays are asserted PBX-log-side
Replayed responses (404/error caches, retransmit absorbs) never traverse a
sipp leg that could assert them: sipp discards responses for completed
transactions, and the Python caller drains replays without asserting.
Rule: **any PBX retransmit/cache replay must be asserted via PBX-log
growth** (`expect_log_growth`), never via peer matching. S3's replay half
(`retransmission detected`) is the template.

## 3. Multi-Via is comma-folded on send
sipp emits one Via line per hop inbound, but folds `Via: A, B` onto one
line outbound. Consequence: branch-cardinality checks
(S5) must comma-split Via values before extracting `branch=`; see
`via_branches()` in `interop/sipassert.py`, which handles both forms. The
old `cut -d, -f1` pipeline got this wrong twice (stray `\r`, folded lines).

## 4. sipp cannot compute digests in custom scenarios
`[authentication]` never answers 401s and `-au`/`-ap` stay inert outside
sipp's built-in flows (both stub-proven) — and nothing in custom XML can
MD5 a challenge anyway. Consequence: **all** authenticated steps go through
Python: REGISTER via `interop/register.py` (bare→401→authed→200, plain and
`qop=auth`), dialog callers via `interop/invite.py` (bare→401→authed→100…),
never through sipp XML. UAS scenarios are unaffected (callees answer, they
don't authenticate).

## 5. Timer-A storms are Python-driven
A 100 Trying does not stop sipp caller retransmission the way strict
RFC 3261 would suggest. But no sipp caller remains on dialog paths, so
the duplicate storm moved to `Dialog.resend_last()` (byte-identical
re-send of the authed INVITE). The absorb proof is UAS-side: exactly one
received INVITE with one PBX branch (S5). Retired with the caller XMLs;
kept here because the storm shape (same branch, consumed nonce) is what
makes absorb-without-rechallenge load-bearing.

## 6. Abort-BYE exits 0 on sipp legs; Python raises directly
A sipp scenario that aborts (e.g. unexpected message during a pause) still
sends a BYE for the dead call and **exits 0**. Consequence: sipp legs
(UAS scenarios, S7) gate on `Successful call` (≥1) / `Failed call` (== 0)
counters via `assert_sipp_ok()`, never on process exit status. Python
`Dialog` failures raise `InviteError` instead — no gate needed, but the
same discipline applies: assert both legs (UAS returncode + counters)
even when the caller drove cleanly.

## 7. Unexpected messages abort, even in `<pause/>` (sipp) or `wait_bye` (Python)
Any datagram arriving during a sipp pause that matches no pending `recv`
aborts the call; Python's `wait_bye` raises on anything but the expected
BYE for the same reason. Two incidents, opposite fixes. Learn both:
- **Keep trailing pauses as tripwires (sipp).** The old
  `uac-alice-callee-bye.xml` ended `send 200 → pause → end`. That pause
  caught a real PBX bug (BYE-200 bounced back to its sender). S4's UAC
  ended at `recv` with no pause, which is why the same bug was invisible
  there. Python-side equivalent: `wait_bye` is strict, so a bounced
  duplicate fails the dialog instead of being skipped.
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

## 9. Media needs pinned ports and loopback source
The relay matches exact endpoints learned from SDP and SIP source, so the
UAS side needs `-mi 127.0.0.1` (default `-mi` is the LAN IP → mismatch →
silent drop) and `-min/-max_rtp_port` equal to the hardcoded `m=audio`
port (auto-selected sockets diverge from the declared port the PBX
matches). Same rule caller-side: `MediaSocket` binds the offered 20000.
`ss -uln` Recv-Q on a relay port with no `Forwarding` lines means the
loop is starved, not the network: the run loop caps sleep at 20ms only
while relay sockets are open (`docs/architecture.md`, event loop).
