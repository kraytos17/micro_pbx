# micro_pbx

A minimal SIP (RFC 3261) registrar and proxy written in Zig. It handles
registration, call setup/teardown, instant messaging, and media relay
(RTP) for small deployments.

## Features

- **SIP methods**: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE (RFC 3428)
- **Registrar**: dual-key AOR lookup (username and `username@domain`) so calls
  route regardless of the domain/host the caller dialed
- **Call state machine**: `proceeding → ringing → answered → established → terminated`,
  with correct CANCEL-vs-2xx race handling
- **Media relay**: rewrites SDP `c=`/`m=` to point at the PBX and forwards RTP
  packets bidirectionally between the two parties; matches on `(IP, port)` to
  prevent cross-talk between concurrent calls
- **Transaction layer**: RFC 3261 timers (T1/T2, Timer B/D), retransmission
  detection, and response caching for INVITE 404s
- **Zero-copy parsing**: the parser is a pure function of the receive buffer —
  no allocation
- **Scoped, timestamped logging**: per-module log scopes with wall-clock
  `HH:MM:SS.mmm` prefixes
- **65 unit tests** across all modules, including an E2E harness that drives
  the full REGISTER→INVITE→180→200→ACK→BYE lifecycle through parsed SIP
  messages without real sockets

## Requirements

- Zig `0.16.0` (see `build.zig.zon`)

## Build & Test

```sh
zig build            # builds ./zig-out/bin/micro_pbx
zig build run        # build and run the PBX
zig build test       # run all unit tests
```

The PBX listens on UDP `0.0.0.0:5060` by default.

## Project Layout

```
src/
├── main.zig           # bootstrap + logging configuration (std_options, pbxLog)
├── pbx.zig            # Pbx struct: owns state, event loop, request/response dispatch
├── transport.zig      # std.Io-based UDP socket wrapper
├── call.zig           # Call state machine + call-table helpers
├── registrar.zig      # AOR → Contact store, dual-keyed
├── proxy.zig          # request/response builders + per-method stateless handlers
├── rtp.zig            # RTP header parsing + media relay sessions
├── sdp.zig            # minimal SDP c=/m= parsing and rewriting
└── sip/
    ├── message.zig    # Method, ResponseClass, Request, Response, Message model
    ├── parser.zig     # byte slice → Message (zero-copy)
    └── transaction.zig # transaction layer: timers, retransmission, response cache
```

### Layering

| Module | Role |
|---|---|
| `main.zig` | entry point; defines `std_options` + `pbxLog` (must live in the root module) |
| `pbx.zig` | stateful core — owns sockets, registrar, transactions, call table, RTP sessions; dispatches requests/responses |
| `proxy.zig` | stateless SIP message building and per-method handlers |
| `call.zig` / `registrar.zig` / `rtp.zig` / `sdp.zig` / `sip/*` | building blocks used by `pbx.zig` |

## Running

```sh
./zig-out/bin/micro_pbx
```

Log output goes to stderr with color. Example:

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
  state (`transport.UdpSocket`, `Registrar`, `TransactionLayer`, call table,
  RTP sessions) and exposes `handleRequest`/`handleResponse`/`on*` methods.
  `main.zig` is a 71-line bootstrap.
- **E2E harness** in `pbx.zig` (7 tests) exercises the actual dispatch methods
  with parsed SIP messages — no real sockets needed, full coverage of the call
  lifecycle, CANCEL races, 404 caching, RTP session creation, and registration
  expiry.
- **RTP relay** was dead (`createSession` never called) until the E2E harness
  exposed it. It's now wired at INVITE time when SDP is present.

## Current Limitations

- **Single-domain, IPv4, UDP only** — no TCP/TLS/SIPS, no IPv6
- **Transaction timers are implemented but not wired into the event loop** —
  `tick()`/`nextTimeout()` exist and are unit-tested, but `Pbx.run()` is still a
  blocking recv loop (the PBX does not yet retransmit on packet loss)
- **No RTP session reaper** — sessions/sockets are only cleaned up on BYE
- **Hardcoded relay IP** (`127.0.0.1`) in SDP rewriting and hardcoded SIP port 5060
- **In-memory registrations** — lost on restart
- **`createSession` port allocator has no free-list** — RTP ports monotonically
  increase (wrapping at 60000) with no reuse tracking

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Soumil Kumar
