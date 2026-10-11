# micro_pbx

A minimal SIP (RFC 3261) registrar and proxy written in Zig. It handles
registration, call setup/teardown, instant messaging, and media relay
(RTP) for small deployments.

## Features

- **SIP methods**: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE (RFC 3428).
  In-dialog duplicate INVITEs are absorbed silently (no re-forward, no
  re-challenge);
  responses to PBX-originated CANCELs terminate at this hop; ACKs with no
  dialog are dropped.
- **Digest authentication** (RFC 3261 + RFC 7616 `qop=auth`, `src/auth.zig`):
  MD5 is ecosystem-mandated, so real protection comes from the storage
  model: the server keeps HA1 verifiers, never passwords. Both `qop=auth`
  and qop-less answers are accepted; nonces are single-use with a 30s TTL
  (swept, capped at 1024 entries); failures always answer plain 401, so
  unknown users and wrong passwords are indistinguishable (no user
  enumeration); stale nonces are explicitly re-challenged per RFC 3261
  (threat model: `docs/auth-security-model.md`).
  REGISTER and INVITE are both challenged (401 + `Authorization`; INVITE
  auth reuses `verifyRequest` unchanged). ACK/BYE/CANCEL/OPTIONS/MESSAGE
  are not — CANCEL is unchallengeable per RFC.
  Seeded users: `alice` / `bob` / `silent`, overridable via a users file
  (`./micro_pbx [users.conf]` — `user:password` lines; missing file keeps
  the seeds).
- **Registrar** (`src/registrar.zig`): dual-key AOR lookup (username and
  `username@domain`) so calls route regardless of the domain/host the caller
  dialed. `Expires: 0` unregisters. Expiry is checked on lookup with a 60s
  background sweep as backstop (`reg_sweep_interval_ms`), so a stale contact
  lingers at most 60s past expiry when nobody looks it up.
- **Call state machine**: `proceeding → ringing → answered → established →
  terminated` (plus `canceling`), with CANCEL-vs-2xx race handling
  (late 200 after CANCEL still establishes, then the dialog ends on BYE).
  Each dialog is one unified `Dialog{call, invite_txn, arena}` entry with a
  per-dialog arena. No parallel maps, no per-field frees.
- **In-dialog response routing follows the request path in reverse.**
  INVITE answers go caller-ward, but a callee-originated BYE is answered
  toward the callee (leg-flip, same rule as request forwarding). A
  caller-only default here once bounced BYE-200s back to their sender and
  starved the callee. Caught by the callee-BYE interop test (flows:
  `docs/architecture.md`).
- **Media relay** (`src/rtp.zig`): sessions are created at INVITE time when
  SDP is present; SDP `c=`/`m=` is rewritten on both legs to point at the
  PBX; relay sockets open on ACK and are session-owned (closed exactly once
  by `removeSession`/`deinit`). Packets route positionally
  (`relayPacket`/`drain`) and match on exact `(IP, port)` endpoints to
  prevent cross-talk between concurrent calls; forwards emanate from the
  destination leg's relay socket so replies return to a polled socket.
  Proven live end to end (`test_s9_rtp_relay`: byte-identical ordered
  echoes both directions). Sessions die on BYE/teardown; an unanswered
  callee is the `0.0.0.0:0` sentinel.
- **Transaction layer** (RFC 3261 timers, `src/sip/transaction.zig`): T1
  500ms with exponential backoff capped at T2 (4s); Timer B / F fire at
  64·T1 = 32s of **elapsed** time (not retransmit count, since backoff would
  stretch expiry into minutes); Timer D 32s. The event loop
  sleeps until `min(next retransmit, next B/F/D lapse)`, so expiry fires on
  time rather than a backoff interval late. Retransmissions are detected and
  absorbed; INVITE 404s are cached and replayed under load. Caps: 512
  dialogs (excess new calls get 503 before any work) and 512 transactions
  (full mapping: `docs/timers.md`).
- **Originated responses**: 100, 180, 200 (incl. 200-for-CANCEL answered
  directly), 401 (+stale), cached 404, 408 on Timer B, 481 for no-dialog
  BYE/CANCEL, 483 on exhausted Max-Forwards (decremented per hop), 503 at
  dialog-table pressure. Everything else (486 busy, 487, in-dialog finals)
  is forwarded, never generated.
- **Zero-copy parsing**: the parser is a pure function of the receive
  buffer; no allocation (`src/sip/parser.zig`, 20 tests).
- **Cross-platform transport**: `std.Io.net` sockets only. No Linux-only
  syscalls (`src/transport.zig`).
- **Scoped, timestamped logging**: per-module log scopes with wall-clock
  `HH:MM:SS.mmm` prefixes. `warn` for survivable wire junk (parse errors);
  `error` is reserved for genuinely broken invariants. The interop suite
  asserts the PBX log stays error-free end to end.

## Requirements

- Zig `0.17.0` (`minimum_zig_version` in `build.zig.zon`)
- For live interop only: SIPp v3.7.7, Python 3.10+, `uv`

## Build & Test

```sh
zig build            # builds ./zig-out/bin/micro_pbx
zig build run        # build and run the PBX
zig build test       # run all 131 unit tests
```

The PBX listens on UDP `0.0.0.0:5060` by default
(`Pbx.init(allocator, io, 5060)` in `src/main.zig`).

### Unit tests (131)

`zig test src/main.zig`: 129 named tests plus 2 `refAllDecls` blocks:

| Module | Tests | Covers |
|---|---|---|
| `sip/parser.zig` | 20 | zero-copy parse, folded Via, 404 responses, SDP bodies |
| `pbx.zig` | 31 (all e2e) | full dispatch lifecycle incl. INVITE auth (bare/wrong/unknown/duplicate), re-INVITE (forward/absorb/answer/timeout), CANCEL races, 404 cache, Timer B 408, Timer D sweep, overload 503, wrong-password stores nothing |
| `sip/transaction.zig` | 14 | tick/retransmit/backoff cap, elapsed Timer B/F, `nextTimeout` lapse term, table-full |
| `proxy.zig` | 13 | builders (byte-exact incl. 408/401/404), Via strip/fold, REGISTER/unregister, OPTIONS 200/404 |
| `call.zig` | 12 | dialog table, arenas, timer helpers, dialog-cap |
| `rtp.zig` | 12 | header parse, loopback relay both directions, session lifecycle, relay-quantum predicate |
| `auth.zig` | 12 | MD5 vectors, qop/non-qop verify, single-use + TTL + cap eviction, HA1-only storage, users-file load |
| `registrar.zig` | 8 | dual-key lookup, expiry, unregister |
| `transport.zig` | 4 | socket wrapper |
| `sdp.zig` | 2 | parse + IP/port rewrite |
| `sip/message.zig` | 1 | model / response classes |

The `pbx.zig` e2e harness drives real dispatch methods through parsed SIP
messages. **Unit tests emit real UDP** (`sendTo` to loopback peers),
so they own loopback ports 5090/5092 — never run `zig test` concurrently
with the interop suite, and never move test addresses into the interop
port map (both sides document the reservation).

### Live interop (SIPp + pytest + Python callers, 17 scenarios)

`./interop.sh` (root wrapper: checks for `uv`/`sipp`/`zig`, translates
`--slow`, passes everything else to pytest):

```sh
./interop.sh                 # fast set, ~8s
./interop.sh --slow          # + S8 Timer-B 408, ~40s extra
./interop.sh -k s4           # select by name substring
./interop.sh --collect-only -q
```

Or directly: `cd interop && uv run pytest [--run-slow]`. Deps come from
`interop/pyproject.toml` (`pytest>=8`, dev group) pinned by
`interop/uv.lock`; `uv run` syncs automatically. No `requirements.txt`:
the lockfile is the single source of truth (`uv export` can emit pip
format if a tool ever demands it).

| Test | Asserts |
|---|---|
| `s1_register` / `s1_register_qop` | bare→401→authed→200 handshake, plain and `qop=auth` |
| `register_wrong_password_fails` | bad credentials never yield 200 (negative control) |
| `register_unknown_user_challenged` | unknown user gets 401 + nonce, never 404 (no enumeration, live) |
| `register_nonce_replay_fails` | captured Authorization resent byte-identical → fresh 401 (single-use nonces, live) |
| `invite_unknown_user_challenged` | unknown-user INVITE → 401 + nonce, never 404/forward (no enumeration, live) |
| `s3_unregistered` | authed INVITE to unregistered-known → 404 once; duplicate replay via PBX log; Expires:0 setup + re-register |
| `s7_max_forwards` | `Max-Forwards: 0` → 483, no dialog (unchallenged — loop protection precedes auth) |
| `garbage_datagrams_ignored` | binary/truncated/empty datagrams → warn-only; PBX stays responsive, no error-log growth |
| `s4_call_and_s5_absorb` | Python authed caller + sipp UAS: handshake, storm duplicate absorbed (1 INVITE + 1 branch at UAS), BYE teardown |
| `s6_cancel` | Python caller CANCELs while proceeding → 200-to-CANCEL + 487, teardown |
| `callee_bye` | Python caller answers callee BYE with 200 |
| `callee_bye_rejected` | caller rejects callee BYE with 403 → routed to callee, dialog removed (probe BYE gets 481), nothing cached |
| `s9_rtp_relay` | live media loop: RTP to relay port from SDP port → echo UAS → byte-identical ordered echoes, both directions logged |
| `s10_reinvite` | caller re-INVITE mid-dialog (new SDP port 20002): forwarded rewritten, answered in established state, echo loop follows, teardown |
| `s8_timer_b` (slow) | Python caller handshakes with silent contact then lingers: 408 at 32.000s after the forwarded leg (Timer B), teardown |
| `no_errors` (always last) | zero `] error(` lines in the whole run's PBX log |

How it works: the session `pbx` fixture rebuilds, spawns the PBX, polls
`pbx.log` for readiness (bounded — fails fast instead of timing out every
scenario against a dead socket), and terminates it afterwards. `register.py`
is imported as a module for all REGISTER steps, `invite.py`'s `Dialog`
drives all dialog callers (sipp can't compute digests); per-run logs archive to
`interop/logs/<timestamp>/` with a `latest` symlink. `sipassert.py` parses
sipp `-trace_msg` logs into structured messages (CRLF + folded-Via handled
once) and gates on sipp's Successful/Failed counters. Never on exit
codes: an abort-BYE after a matched 408 still exits 0.

SIPp 3.7.7 quirks the suite is built around (catalog: `docs/sipp-quirks.md`;
discipline: `docs/testing-discipline.md`; all stub-proven, all
commented at the use site): responses correlate only for
keyword-generated Call-IDs; responses for completed transactions are
discarded (duplicate assertions go via the PBX log, not sipp matching);
multi-Via is comma-folded on send; `[authentication]` never answers 401s
in custom scenarios (hence `register.py`); Timer A ignores 100s.

**Loopback port map** (fixed: sipp and the PBX route by address):

| Port | Owner |
|---|---|
| 5060 | PBX |
| 5061 | sipp caller (UAC) |
| 5063 | silent contact (nothing listens; must differ from 5061 or the PBX routes the INVITE back to the caller) |
| 5070 | sipp callee (UAS) / registered-contact port |
| 5090 / 5092 | unit-test peers (see above) |

## Docs

Depth behind this README lives in [`docs/`](docs/index.md): rationale,
flows, and tribal knowledge. README is quickstart + inventory; the split
rule and per-page guide are in `docs/index.md`:

- [`docs/roadmap.md`](docs/roadmap.md) — deferred work with prerequisites
- [`docs/sipp-quirks.md`](docs/sipp-quirks.md) — stub-proven SIPp behaviors
- [`docs/testing-discipline.md`](docs/testing-discipline.md) — ports, gates, author checklist
- [`docs/auth-security-model.md`](docs/auth-security-model.md) — threat model
- [`docs/timers.md`](docs/timers.md) — RFC timer mapping + decisions
- [`docs/architecture.md`](docs/architecture.md) — request flows, ownership

## Project Layout

```
src/
├── main.zig           # 73-line bootstrap + logging config (std_options, pbxLog)
├── pbx.zig            # Pbx struct: owns state, event loop, request/response dispatch
├── auth.zig           # digest auth: HA1 store, nonces, qop verify
├── transport.zig      # std.Io-based UDP socket wrapper
├── call.zig           # Dialog table (Dialog{call, invite_txn, arena}) + helpers
├── registrar.zig      # AOR → Contact store, dual-keyed, expiry + unregister
├── proxy.zig          # request/response builders + per-method stateless handlers
├── rtp.zig            # RTP header parsing + media relay sessions
├── sdp.zig            # minimal SDP c=/m= parsing and rewriting
└── sip/
    ├── message.zig    # Method, ResponseClass, Request, Response, Message model
    ├── parser.zig     # byte slice → Message (zero-copy)
    └── transaction.zig # timers, retransmission, response cache
interop.sh            # repo-root wrapper (prereq checks, --slow, pytest passthrough)
interop/
├── test_interop.py    # 13 ordered live scenarios (file order = run order)
├── conftest.py        # PBX lifecycle, log archiving, sipp runners, log-growth asserts
├── register.py        # digest-auth REGISTER client (importable + CLI)
├── sipassert.py       # structured sipp-log parser + sipp counter gate
├── invite.py          # digest-auth INVITE dialog driver (sipp can't do digests)
├── pyproject.toml     # pytest>=8 dev dependency, slow marker
├── uv.lock            # pinned tree (single source of truth)
├── users.conf         # interop credentials (user:password lines, passed to the PBX)
├── uac-mf0.xml        # sole surviving caller scenario (483 precedes auth)
└── uas-*.xml          # SIPp callee scenarios (answer only, never authenticate)
```

### Layering

| Module | Role |
|---|---|
| `main.zig` | entry point; defines `std_options` + `pbxLog` (must live in the root module) |
| `pbx.zig` | stateful core: owns sockets, auth, registrar, transactions, call table, RTP sessions; dispatches requests/responses; retransmit timers driven via `receiveTimeout` + `handleTimeout`, resend-before-sweep |
| `auth.zig` | digest verification + nonce table; authentication failures are *answers* (401), never errors |
| `proxy.zig` | stateless SIP message building and per-method handlers |
| `call.zig` / `registrar.zig` / `rtp.zig` / `sdp.zig` / `sip/*` | building blocks used by `pbx.zig` |
| `interop/*` | live verification against real SIPp peers (see above) |

## Running

```sh
./zig-out/bin/micro_pbx [users.conf]
```

Optional argv path to a `user:password` credentials file (defaults to
`./users.conf`; missing file warns and keeps seeded users). Log output
goes to stderr with color. Example:

```
[14:03:22.145] info(main): PBX listening on 0.0.0.0:5060
[14:03:22.512] info(main): REGISTER sip:alice@192.168.50.55:5060 call-id=...
[14:03:23.004] info(main): INVITE sip:bob@192.168.50.55:5060 call-id=...
[14:03:24.127] info(main): call ... answered (200 OK)
[14:03:24.200] debug(rtp): RTP: Forwarding from caller to callee: 172 bytes
```

## Manual E2E Test with baresip

Two baresip instances (Alice, Bob) registering to the PBX, then a call.

1. **Start the PBX**:
   ```sh
   ./zig-out/bin/micro_pbx
   ```
2. **Configure two baresip instances** (distinct config dirs and SIP ports).
   Create `~/.baresip/config` and `~/.baresip-bob/config`:
   - **Alice** (`sip_listen 0.0.0.0:5062`):
     - accounts: `<sip:alice@192.168.50.55:5060>;regint=3600`
     - For headless machines, comment out `audio_player`/`audio_source`/`audio_alert`
       (do not set them to `none`) and enable `module ausine.so` for a sine tone.
   - **Bob** (`sip_listen 0.0.0.0:5064`):
     - accounts: `<sip:bob@192.168.50.55:5060>;regint=3600;answerdelay=0;sip_autoanswer=yes`
     - Same audio setup.
   - Both need `net_interface wlo1` (or your machine's LAN interface) to avoid
     baresip's "no laddr" loopback routing issue.
3. **Launch both**:
   ```sh
   baresip -f ~/.baresip
   baresip -f ~/.baresip-bob
   ```
   Wait for `200 OK [1 binding]` in each.
4. **Dial** (Alice console). Note: baresip v4.6.0 has a bug where the long-form
   `/dial sip:...` command mangles the URI. Use the single-key shortcut instead:
   ```
   d sip:bob@192.168.50.55:5060
   ```
   Bob auto-answers. The PBX logs the INVITE forward and RTP relay activity.
5. **Hang up**:
   ```
   /hangup
   ```

> **Notes**:
> - baresip has a known issue dialing loopback URIs (`no laddr for 127.0.0.1`).
>   Register and dial via the machine's LAN IP (e.g. `192.168.50.55`) instead
>   of `127.0.0.1`, and set `net_interface wlo1`.
> - The `d` shortcut bypasses a v4.6.0 bug where `/dial` passes the command
>   token itself as the URI argument.

## Architecture Highlights

- **Most logic lives in `Pbx`** (`src/pbx.zig`), a struct that owns all mutable
  state (`transport.UdpSocket`, `Auth`, `Registrar`, `TransactionLayer`, call
  table, RTP sessions) and dispatches through `handleResponse` /
  `handleTimeout` / `on*` methods. `main.zig` is a 73-line bootstrap.
- **E2E harness** in `pbx.zig` (31 tests) exercises the actual dispatch methods
  with parsed SIP messages. Full coverage of the call lifecycle, CANCEL
  races, 404 caching, 408/Timer D expiry, overload 503, RTP session creation,
  and registration expiry. These tests emit real loopback UDP (hence the
  port reservations above), and the pytest suite replays the same flows
  against live SIPp peers.
- **RTP relay** was dead (`createSession` never called) until the E2E harness
  exposed it. It's now wired at INVITE time when SDP is present, with relay
  sockets opening on ACK.
- **Unified dialogs** (`src/call.zig`): one `Dialog{call, invite_txn, arena}`
  table with per-dialog arenas replaced parallel maps and per-field frees;
  dead APIs (`putCall`, `setCompleted`, per-field free helpers) were deleted
  rather than deprecated.

## Current Limitations

- **Single-domain, IPv4, UDP only**: no TCP/TLS/SIPS, no IPv6, no SRTP
- **File-backed credentials, seeds as fallback**: `user:password` lines
  from an argv path (else `./users.conf`); missing file warns and keeps the
  `Pbx.init` seeds. Rotation needs a restart (no hot-reload).
- **In-memory registrations**: lost on restart, no persistence
- **Hardcoded relay IP** (`127.0.0.1`) in SDP rewriting and hardcoded SIP port
  5060: the PBX anchors media to loopback regardless of interface
- **Re-INVITE / hold-resume / session timers**: not implemented ([roadmap](docs/roadmap.md)).
  Mid-dialog duplicate INVITEs are absorbed, not renegotiated.
- **RTP port allocator has no free-list**: relay ports start at 10000,
  allocate in steps of 4, wrap at 60000, with no reuse tracking
- **Bounded tables shed load by design, not gracefully**: 512 dialogs
  (excess → 503), 512 transactions, 1024 nonces; nonce pressure evicts under
  the cap
- **Graph staleness caveat for AI-assisted work**: the repo keeps a
  codebase-memory knowledge graph, but it lags deletions (it still lists
  `putCall`, `createInviteTransaction`, and the old `run.sh`). Trust
  ripgrep + the compiler over the graph for existence claims.

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Soumil Kumar
