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
  packets bidirectionally between the two parties
- **Transaction layer**: RFC 3261 timers (T1/T2, Timer B/D), retransmission
  detection, and response caching for INVITE 404s
- **Zero-copy parsing**: the parser is a pure function of the receive buffer —
  no allocation
- **Scoped, timestamped logging**: per-module log scopes with wall-clock
  `HH:MM:SS.mmm` prefixes

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
    ├── message.zig    # Method, Request, Response, Message model
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
[14:03:22.512] info(main): REGISTER sip:alice@192.168.50.55:5060 call-id=...@...
[14:03:23.004] info(main): INVITE sip:bob@192.168.50.55:5060 call-id=...@...
```

## Manual E2E Test with baresip

Two baresip instances (Alice, Bob) registering to the PBX, then a call.

1. **Start the PBX**:
   ```sh
   ./zig-out/bin/micro_pbx
   ```
2. **Configure two baresip instances** (distinct config dirs and SIP ports):
   ```sh
   mkdir -p ~/.baresip-alice ~/.baresip-bob
   ```
   Each `config` needs `sip_listen` set to a distinct port (e.g. `5062` for
   Alice, `5064` for Bob) and, for headless machines,
   `audio_player none` / `audio_source none` (or use the `ausine` sine module
   for real media flow).
   - `~/.baresip-alice/accounts`: `<sip:alice@192.168.50.55:5060>;regint=3600`
   - `~/.baresip-bob/accounts`: `<sip:bob@192.168.50.55:5060>;regint=3600;answerdelay=0;sip_autoanswer=yes`
3. **Launch both**:
   ```sh
   baresip -f ~/.baresip-alice
   baresip -f ~/.baresip-bob
   ```
   Wait for `200 OK [1 binding]` in each.
4. **Dial** (Alice console):
   ```
   dial sip:bob@192.168.50.55:5060
   ```
   Bob auto-answers. The PBX logs the INVITE forward and RTP relay activity.

> **Note**: baresip has a known issue dialing loopback URIs (`no laddr for
> 127.0.0.1`). Register and dial via the machine's LAN IP (e.g.
> `192.168.50.55`) instead of `127.0.0.1`.

## Current Limitations

- **Single-domain, IPv4, UDP only** — no TCP/TLS/SIPS, no IPv6
- **RTP relay matches by source port** (IP+port for multi-NAT deployment is future work)
- **Transaction timers are implemented but not wired into the event loop** —
  `tick()`/`nextTimeout()` exist and are unit-tested, but `Pbx.run()` is still a
  blocking recv loop (the PBX does not yet retransmit on packet loss)
- **No RTP session reaper** — sessions/sockets are only cleaned up on BYE
- **Hardcoded relay IP** (`127.0.0.1`) in SDP rewriting and hardcoded SIP port
- **In-memory registrations** — lost on restart

## License

None specified.
