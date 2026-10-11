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
`Auth.addUser` (`src/auth.zig:198`) hashes `user:realm:password` to HA1 at
seed time and stores only the 32-hex-char verifier (unit test
`addUser stores HA1 verifiers, never passwords` asserts a stored entry can
only be HA1). A database read yields challenge-answering power for live
nonces (same as any digest deployment) but no password recovery, and
test-only passwords live behind an explicit helper (`src/pbx.zig:715`),
never beside the verifier store.

## Challenge hygiene
- **Single-use nonces.** Each 401 mints a nonce; a correct answer consumes
  it. Replays get a fresh 401 (interop `test_register_wrong_password_fails`
  exercises the failure path live; full nonce-replay coverage is future
  test work).
- **30s TTL + sweeper** (`nonce_ttl_secs`, `src/auth.zig:21`; sweep inline
  at verify, `src/auth.zig:216-226`). Stolen challenges rot fast.
- **1024-entry cap** (`max_nonces`, `src/auth.zig:25`; arbitrary entries
  evicted under pressure, `src/auth.zig:236`). Unauthenticated table growth
  is bounded: INVITE floods can't OOM the nonce store.
- **Accept-both qop.** `qop=auth` answers (bound to client nonce/nc/cnonce)
  and qop-less answers both verify; `qop` binds responses to client nonces
  where present. Covered live by `test_s1_register_qop` and at the builder
  level (`clientResponse`, `src/auth.zig:131`).

## No user enumeration
All verification failures (unknown user, wrong password, bad nonce) take
the identical path: `verifyRequest` errors → `sendUnauthorized`
(`src/proxy.zig:212-218`), a plain 401 with a fresh nonce. The code comment
says it directly: *authentication failures are answers, not errors*.
Locked in live by `test_register_unknown_user_challenged` (unknown user
gets 401 + nonce, never 404) and in unit tests (`e2e REGISTER with wrong
password stores nothing`, `src/pbx.zig:1049`).

## Stale handling
Expired-but-once-valid nonces answer `stale=true` (`src/auth.zig:156`)
and are explicitly re-challenged per RFC 3261 (`src/proxy.zig:216`), so
honest clients with clock skew retry instead of failing.

## Explicit non-protections
- **Transport is bare UDP on loopback.** Digest over the open internet
  without TLS is observer-readable challenge/response (offline dictionary
  attacks apply to weak passwords). Deployment behind a VPN or trusted
  LAN is assumed, not enforced.
- **Seeded credentials** (`alice`/`bob`/`silent`, `src/pbx.zig:58-60`).
  No password file yet (roadmap); credential rotation means a rebuild.
- **REGISTER-only auth.** INVITEs are unauthenticated until the roadmap's
  407 path lands; the PBX currently trusts the loopback for dialog setup.
