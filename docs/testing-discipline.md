# Testing Discipline

Rules earned from three debugging sessions. Violating any of them has
produced at least one real flake or false-pass.

## The serial-execution rule
**Never run `zig test` and pytest concurrently, and never run two pytest
instances concurrently.** Both suites emit real UDP on loopback, and sipp
aborts on any unexpected datagram. The recorded incident: a parallel
`zig test` sent a 401 for `alicereg@127.0.0.1` (format-built as
`{name}reg@…` in `registerHandshake`, `src/pbx.zig:724`; invisible to
literal grep) from `test_alice_addr` (then `127.0.0.1:5070`) into the S4
UAS socket. Fix was port separation (unit peers moved to 5090/5092), but
separation only covers *known* collisions. Serial execution covers unknown
ones. CI must run the suites sequentially.

## Loopback port map
Fixed: the PBX routes by source address, so these are load-bearing:

| Port | Owner | Notes |
|---|---|---|
| 5060 | PBX | `Pbx.init(allocator, io, 5060)`, `src/main.zig:64` |
| 5061 | sipp caller (UAC) | `UAC_PORT`, `interop/conftest.py` |
| 5063 | silent contact | nothing listens; must differ from 5061, or INVITEs route back to the caller |
| 5070 | sipp callee (UAS) / registered-contact port | `UAS_PORT` |
| 5090 / 5092 | unit-test peers | `test_alice_addr` / `test_bob_addr`, `src/pbx.zig:664-666` |
| 20000 | Python caller RTP (bound by `MediaSocket`, matches offered SDP) | media must originate here (exact-endpoint match) |
| 20002 | re-INVITE caller RTP (rebound `MediaSocket`, S10 port move) | same rule after renegotiation |
| 4000–4001 | sipp UAS media+RTCP (pinned via `-min/-max_rtp_port`) | must equal the hardcoded `m=audio 4000` (PBX matches declared ports) |
| 10000+ | PBX relay ports (step 4, wrap 60000) | advertised in rewritten SDP, learned from 200's `m=` |

Both sides carry reservation comments; update both if the map changes.

## Assertion tiers
1. **sipp counters, not exit codes:** `assert_sipp_ok()`:
   `Successful ≥ 1` and `Failed == 0`, on both UAC and UAS legs
   (abort-BYE exits 0; see `docs/sipp-quirks.md` §6).
2. **PBX-log growth:** `expect_log_growth()` for must-happen invariants
   (replay, teardowns, 408), `expect_no_log_growth()` for must-stay-clean
   ones. The log is cumulative per run, so capture before-counts.
3. **Structured message asserts:** `parse_sipp_msg_log()` + helpers for
   wire-shape claims (S5 branch cardinality). Never `grep/cut/sort` SIP
   logs in shell: three separate bugs came from that pipeline.

## Scenario-author checklist
- [ ] Register via `register()` (imported) before starting the UAS;
      foreground order, then `sleep(1)` after UAS spawn.
- [ ] Dialog callers go through `invite.Dialog` (sipp can't do digests):
      handshake (bare CSeq 1 → 401 → authed CSeq 2), then drive.
- [ ] ACK/CANCEL echo the *answered* INVITE's CSeq (2 after the 401 dance,
      never 1: sipp aborts on mismatch).
      Fresh in-dialog requests bump as usual (BYE CSeq 3).
- [ ] New dialog needs a new Call-ID and fresh branch values. Never reuse
      another scenario's.
- [ ] UAS `recv` timeouts ≥ 15s for INVITE (PBX-side work happens first);
      8s is fine for in-dialog steps.
- [ ] No `<pause/>` before a `recv` (tied-pause race); keep trailing pauses
      as regression tripwires (`wait_bye` is strict for the same reason).
- [ ] Teardown assert (`terminated (…)`) around every dialog test.
- [ ] `test_no_errors` stays last in `test_interop.py`: file order is run
      order, and it judges the whole run's log.
- [ ] New quirk found → `docs/sipp-quirks.md`. New deferred work →
      `docs/roadmap.md`. Same PR as the test.

## Negative controls
Gates get proven, not trusted: the counter gate was validated against
green / failed-call / zero-success / missing-file fixtures, and the
suite carries a live wrong-password test. Any new gate helper ships with
its own fail-closed controls.
