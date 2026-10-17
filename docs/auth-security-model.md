# Authentication Security Model

Digest auth per RFC 3261 + RFC 7616 `qop=auth` (`src/auth.zig`). This page
is the threat model behind the implementation; the code header states the
one-line version.

## What the crypto does and doesn't give
MD5 is mandated by the SIP ecosystem: every phone and trunk speaks it.
So collision resistance is not the security argument and was never
evaluated. Forgery here means *preimage*: answering a fresh 401 requires
the password (or HA1) at challenge time, and MD5's preimage resistance is
unthreatened. The design puts its weight everywhere else.

## Storage: verifiers, never passwords
`Auth.addUser` (`src/auth.zig:202`) hashes `user:realm:password` to HA1 at
seed time and stores only the 32-hex-char verifier (unit test
`addUser stores HA1 verifiers, never passwords` asserts a stored entry can
only be HA1). A database read yields challenge-answering power for live
nonces (same as any digest deployment) but no password recovery, and
test-only passwords live behind an explicit helper (`src/pbx.zig:896`),
never beside the verifier store.

## Challenge hygiene
- **Single-use nonces.** Each 401 mints a nonce; a correct answer consumes
  it. Replays get a fresh 401, proven live (`test_register_nonce_replay_fails`
  resends a captured Authorization byte-identical and gets 401).
- **30s TTL + sweeper** (`nonce_ttl_secs`, `src/auth.zig:21`; sweep inline
  at issue, `src/auth.zig:258-270`). Stolen challenges rot fast.
- **1024-entry cap** (`max_nonces`, `src/auth.zig:25`; arbitrary entries
  evicted under pressure, `src/auth.zig:277`). Unauthenticated table growth
  is bounded: INVITE floods can't OOM the nonce store.
- **Accept-both qop.** `qop=auth` answers (bound to client nonce/nc/cnonce)
  and qop-less answers both verify; `qop` binds responses to client nonces
  where present. Covered live by `test_s1_register_qop` and at the builder
  level (`clientResponse`, `src/auth.zig:114`).

## No user enumeration
All verification failures (unknown user, wrong password, bad nonce) take
the identical path: `verifyRequest` errors → `sendUnauthorized`
(`src/proxy.zig:213-218`), a plain 401 with a fresh nonce. The code comment
says it directly: *authentication failures are answers, not errors*.
Locked in live by `test_register_unknown_user_challenged` (unknown user
gets 401 + nonce, never 404) and in unit tests (`e2e REGISTER with wrong
password stores nothing`, `src/pbx.zig:1374`).

## Stale handling
Expired-but-once-valid nonces answer `stale=true` (`src/auth.zig:158`)
and are explicitly re-challenged per RFC 3261 (`src/proxy.zig:218`), so
honest clients with clock skew retry instead of failing.

## Explicit non-protections
- **Transport is bare UDP on loopback.** Digest over the open internet
  without TLS is observer-readable challenge/response (offline dictionary
  attacks apply to weak passwords). Deployment behind a VPN or trusted
  LAN is assumed, not enforced.
- **File-backed credentials, seeds as fallback.** `main` loads
  `user:password` lines from an argv path (else `./users.conf`) through
  `Auth.loadUsersFile`, which seeds via `addUser`, so the HA1-only
  invariant holds for file users too. Missing file warns and keeps the
  `Pbx.init` seeds (`alice`/`bob`/`silent`); malformed lines warn-skip.
  Rotation still needs a restart (no hot-reload).
- **REGISTER + INVITE challenged; all others open.** INVITEs authenticate
  with 401 + `Authorization` (same machinery, method-agnostic verifier),
  challenged before lookup so unknown users never reach the registrar.
  ACK/BYE/CANCEL/OPTIONS/MESSAGE are unchallenged; CANCEL cannot be
  challenged per RFC, and in-dialog requests ride the authenticated
  INVITE's dialog. The PBX still trusts the loopback for everything else.
