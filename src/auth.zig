//! SIP Digest authentication (RFC 3261, RFC 7616 qop=auth).
//!
//! The PBX challenges REGISTER requests with 401 + WWW-Authenticate and
//! verifies the Authorization header against an in-memory user table.
//! All hashing is streaming (zero-alloc); response comparison is
//! constant-time over the hex digests.
//!
//! Security model: MD5 is mandated by the ecosystem.
//! Real protection comes from elsewhere: the server stores HA1 verifier
//! hashes, nonces are single-use with a short TTL,
//! qop binds responses to client nonces, and mismatches reveal nothing
//! about which credential was wrong (no user enumeration).

const std = @import("std");

const msg = @import("sip/message.zig");

const log = std.log.scoped(.auth);

pub const realm = "pbx";
pub const nonce_ttl_secs: i64 = 30;
pub const nonce_bytes = 16;
// Bounds unauthenticated table growth (bare REGISTER floods). Victims of
// an arbitrary eviction simply get a fresh 401 to retry with. Tunable.
pub const max_nonces: usize = 1024;

pub const AuthError = error{
    MissingCredentials,
    UnknownUser,
    UnknownNonce,
    StaleNonce,
    BadResponse,
};

/// Parsed Authorization header. All slices borrow the header value.
/// qop/nc/cnonce are "" when the client answers without quality of
/// protection (RFC 2069 style, still accepted).
pub const Credentials = struct {
    username: []const u8,
    realm: []const u8,
    nonce: []const u8,
    uri: []const u8,
    response: []const u8,
    qop: []const u8,
    nc: []const u8,
    cnonce: []const u8,
};

/// Parses `Digest username="..", realm="..", nonce="..", uri="..",
/// response=".."` in any order. Values may be quoted or bare.
/// Commas inside quoted values are not supported (our nonces, realm, and
/// usernames never contain them).
pub fn parseAuthorization(raw: []const u8) !Credentials {
    var creds = Credentials{
        .username = "",
        .realm = "",
        .nonce = "",
        .uri = "",
        .response = "",
        .qop = "",
        .nc = "",
        .cnonce = "",
    };

    const trimmed = std.mem.trim(u8, raw, " ");
    const body = if (std.mem.startsWith(u8, trimmed, "Digest"))
        std.mem.trim(u8, trimmed["Digest".len..], " ")
    else
        return error.MissingCredentials;

    var it = std.mem.splitScalar(u8, body, ',');
    while (it.next()) |part| {
        const eq = std.mem.findScalar(u8, part, '=') orelse continue;
        const key = std.mem.trim(u8, part[0..eq], " ");
        var value = std.mem.trim(u8, part[eq + 1 ..], " ");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1 .. value.len - 1];
        }
        if (std.mem.eql(u8, key, "username")) {
            creds.username = value;
        } else if (std.mem.eql(u8, key, "realm")) {
            creds.realm = value;
        } else if (std.mem.eql(u8, key, "nonce")) {
            creds.nonce = value;
        } else if (std.mem.eql(u8, key, "uri")) {
            creds.uri = value;
        } else if (std.mem.eql(u8, key, "response")) {
            creds.response = value;
        } else if (std.mem.eql(u8, key, "qop")) {
            creds.qop = value;
        } else if (std.mem.eql(u8, key, "nc")) {
            creds.nc = value;
        } else if (std.mem.eql(u8, key, "cnonce")) {
            creds.cnonce = value;
        }
    }
    if (creds.username.len == 0 or creds.nonce.len == 0 or creds.response.len == 0) {
        return error.MissingCredentials;
    }
    return creds;
}

/// MD5 hex (lowercase) of the given parts, streamed without allocation.
fn md5Hex(parts: []const []const u8) [32]u8 {
    var hasher = std.crypto.hash.Md5.init(.{});
    for (parts) |part| hasher.update(part);
    var digest: [16]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

/// Renders a client Authorization header value for the given credentials.
/// Used by tests acting as the client; sipp does this itself over the wire.
pub fn clientResponse(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    nonce: []const u8,
    method: []const u8,
    uri: []const u8,
) ![]u8 {
    const ha1 = md5Hex(&.{ username, ":", realm, ":", password });
    const ha2 = md5Hex(&.{ method, ":", uri });
    const expected = md5Hex(&.{ ha1[0..], ":", nonce, ":", ha2[0..] });
    return allocator.print(
        "Digest username=\"{s}\", realm=\"{s}\", nonce=\"{s}\", uri=\"{s}\", response=\"{s}\"",
        .{ username, realm, nonce, uri, expected },
    );
}

/// Renders a client Authorization header value with qop=auth.
/// Used by tests acting as a qop-capable client.
pub fn clientResponseQop(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    nonce: []const u8,
    method: []const u8,
    uri: []const u8,
    cnonce: []const u8,
    nc: []const u8,
) ![]u8 {
    const ha1 = md5Hex(&.{ username, ":", realm, ":", password });
    const ha2 = md5Hex(&.{ method, ":", uri });
    const expected = md5Hex(&.{ ha1[0..], ":", nonce, ":", nc, ":", cnonce, ":auth:", ha2[0..] });
    return allocator.print(
        "Digest username=\"{s}\", realm=\"{s}\", nonce=\"{s}\", uri=\"{s}\", response=\"{s}\", qop=auth, nc={s}, cnonce=\"{s}\"",
        .{ username, realm, nonce, uri, expected, nc, cnonce },
    );
}

/// Renders a WWW-Authenticate challenge header value.
pub fn challenge(allocator: std.mem.Allocator, nonce: []const u8, stale: bool) ![]u8 {
    if (stale) {
        return allocator.print(
            "Digest realm=\"{s}\", nonce=\"{s}\", algorithm=MD5, qop=\"auth\", stale=true",
            .{ realm, nonce },
        );
    }
    return allocator.print(
        "Digest realm=\"{s}\", nonce=\"{s}\", algorithm=MD5, qop=\"auth\"",
        .{ realm, nonce },
    );
}

pub const Auth = struct {
    nonces: std.StringHashMap(i64),
    /// username -> HA1 verifier hash (hex). Passwords never rest in memory:
    /// verification needs only HA1, so a server breach yields verifiers,
    /// not credentials.
    users: std.StringHashMap([32]u8),
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Auth {
        return .{
            .nonces = std.StringHashMap(i64).init(allocator),
            .users = std.StringHashMap([32]u8).init(allocator),
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *Auth) void {
        var nit = self.nonces.iterator();
        while (nit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }

        self.nonces.deinit();
        var uit = self.users.iterator();
        while (uit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.users.deinit();
    }

    pub fn addUser(self: *Auth, username: []const u8, password: []const u8) !void {
        const ha1 = md5Hex(&.{ username, ":", realm, ":", password });
        const gop = try self.users.getOrPut(username);
        if (gop.found_existing) {
            gop.value_ptr.* = ha1;
        } else {
            errdefer _ = self.users.remove(username);
            gop.key_ptr.* = try self.allocator.dupe(u8, username);
            errdefer self.allocator.free(gop.key_ptr.*);
            gop.value_ptr.* = ha1;
        }
    }

    /// Loads `user:password` lines (`#` comments and blanks skipped) and
    /// seeds verifiers via addUser — passwords are never retained, so the
    /// HA1-only invariant holds for file-loaded users too. Malformed lines
    /// are warn-skipped, never fatal. Returns users loaded. An unreadable
    /// file propagates to the caller (main falls back to seeds).
    pub fn loadUsersFile(self: *Auth, path: []const u8) !usize {
        const data = try std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(65536));
        defer self.allocator.free(data);
        return self.loadUsersData(path, data);
    }

    /// Parses users-file content (split for unit tests; see loadUsersFile).
    pub fn loadUsersData(self: *Auth, path: []const u8, data: []const u8) !usize {
        var loaded: usize = 0;
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            const sep = std.mem.find(u8, line, ":") orelse {
                log.warn("users file {s}: skipping malformed line", .{path});
                continue;
            };

            const user = std.mem.trim(u8, line[0..sep], " \t");
            const pass = std.mem.trim(u8, line[sep + 1 ..], " \t");
            if (user.len == 0 or pass.len == 0) {
                log.warn("users file {s}: skipping malformed line", .{path});
                continue;
            }

            try self.addUser(user, pass);
            loaded += 1;
        }
        return loaded;
    }

    fn nowSecs(self: *Auth) i64 {
        return std.Io.Timestamp.now(self.io, std.Io.Clock.real).toSeconds();
    }

    /// Issues a fresh nonce (returned by value; the table keeps its own
    /// copy) and drops expired ones.
    pub fn issueNonce(self: *Auth) ![32]u8 {
        const now = self.nowSecs();
        // Sweep expired nonces; the table stays tiny.
        var it = self.nonces.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* <= now) {
                const expired = entry.key_ptr.*;
                _ = self.nonces.remove(expired);

                self.allocator.free(expired);
                it = self.nonces.iterator();
            }
        }

        var raw: [nonce_bytes]u8 = undefined;
        std.Io.random(self.io, &raw);
        // Hard cap: evict arbitrary entries past it *before* inserting, so
        // the fresh nonce always survives. A victim's in-flight handshake
        // just gets a fresh 401 to retry with (self-healing).
        while (self.nonces.count() >= max_nonces) {
            var vit = self.nonces.iterator();
            const victim = vit.next() orelse break;
            const victim_key = victim.key_ptr.*;
            _ = self.nonces.remove(victim_key);
            self.allocator.free(victim_key);
        }

        const hex = std.fmt.bytesToHex(raw, .lower);
        const key = try self.allocator.dupe(u8, hex[0..]);
        errdefer self.allocator.free(key);
        try self.nonces.put(key, now + nonce_ttl_secs);
        return hex;
    }

    /// Verifies a request's Authorization header. Returns the username
    /// (borrowed) for logging. Unknown users get a plain mismatch error
    /// on purpose: no user enumeration. A present qop must be "auth"
    /// (the only mode we offer) with nc and cnonce; absent qop falls
    /// back to the legacy response shape.
    pub fn verifyRequest(self: *Auth, req: msg.Request) ![]const u8 {
        const raw = req.authorization orelse return error.MissingCredentials;
        const creds = try parseAuthorization(raw);
        const ha1hex = self.users.get(creds.username) orelse return error.UnknownUser;
        const expires_at = self.nonces.get(creds.nonce) orelse return error.UnknownNonce;
        if (expires_at <= self.nowSecs()) {
            if (self.nonces.fetchRemove(creds.nonce)) |kv| {
                self.allocator.free(kv.key);
            }
            return error.StaleNonce;
        }

        const ha2 = md5Hex(&.{ req.method.toSlice(), ":", creds.uri });
        var expected: [32]u8 = undefined;
        if (creds.qop.len > 0) {
            if (!std.mem.eql(u8, creds.qop, "auth")) return error.BadResponse;
            if (creds.nc.len == 0 or creds.cnonce.len == 0) return error.BadResponse;
            expected = md5Hex(&.{ ha1hex[0..], ":", creds.nonce, ":", creds.nc, ":", creds.cnonce, ":auth:", ha2[0..] });
        } else {
            expected = md5Hex(&.{ ha1hex[0..], ":", creds.nonce, ":", ha2[0..] });
        }
        if (creds.response.len != expected.len) return error.BadResponse;

        var provided: [32]u8 = undefined;
        @memcpy(&provided, creds.response);
        if (!std.crypto.timing_safe.eql([32]u8, expected, provided)) {
            return error.BadResponse;
        }
        // Single-use nonces: consume on success so captures cannot replay.
        // The client's next request takes a fresh 401 transparently.
        if (self.nonces.fetchRemove(creds.nonce)) |kv| {
            self.allocator.free(kv.key);
        }
        return creds.username;
    }
};

test "RFC 2617 digest known-answer vector" {
    // RFC 2617 §3.5: Mufasa/Circle Of Life.
    const ha1 = md5Hex(&.{ "Mufasa", ":", "testrealm@host.com", ":", "Circle Of Life" });
    try std.testing.expectEqualStrings("939e7578ed9e3c518a452acee763bce9", ha1[0..]);

    const ha2 = md5Hex(&.{ "GET", ":", "/dir/index.html" });
    try std.testing.expectEqualStrings("39aff3a2bab6126f332b942af96d3366", ha2[0..]);

    const response = md5Hex(&.{
        ha1[0..],
        ":",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        ":",
        ha2[0..],
    });
    try std.testing.expectEqualStrings("670fd8c2df070c60b045671b8b24ff02", response[0..]);
}

test "parseAuthorization handles ordering and quoting" {
    const creds = try parseAuthorization(
        "Digest response=\"abc123\", username=\"alice\", realm=\"pbx\", uri=\"sip:pbx\", nonce=\"n1\"",
    );
    try std.testing.expectEqualStrings("alice", creds.username);
    try std.testing.expectEqualStrings("pbx", creds.realm);
    try std.testing.expectEqualStrings("n1", creds.nonce);
    try std.testing.expectEqualStrings("sip:pbx", creds.uri);
    try std.testing.expectEqualStrings("abc123", creds.response);
}

test "parseAuthorization rejects non-digest and incomplete headers" {
    try std.testing.expectError(error.MissingCredentials, parseAuthorization("Basic dXNlcg=="));
    try std.testing.expectError(error.MissingCredentials, parseAuthorization("Digest username=\"alice\""));
}

fn authTestRequest(auth_header: ?[]const u8) msg.Request {
    return .{
        .method = .REGISTER,
        .request_uri = "sip:pbx.local",
        .via = "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKauth",
        .via_branch = "z9hG4bKauth",
        .via_branch2 = "",
        .from = "<sip:alice@pbx.local>;tag=t",
        .from_tag = "t",
        .to = "<sip:alice@pbx.local>",
        .to_tag = null,
        .call_id = "authcall",
        .cseq_num = 1,
        .cseq_method = .REGISTER,
        .contact = null,
        .expires = null,
        .content_type = null,
        .max_forwards = null,
        .authorization = auth_header,
        .body = "",
    };
}

test "verifyRequest round-trips a client response" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();
    try auth.addUser("alice", "alicepass");

    const nonce = try auth.issueNonce();

    const header = try clientResponse(
        std.testing.allocator,
        "alice",
        "alicepass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
    );
    defer std.testing.allocator.free(header);

    const username = try auth.verifyRequest(authTestRequest(header));
    try std.testing.expectEqualStrings("alice", username);
}

test "verifyRequest rejects tampered and unknown credentials" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();
    try auth.addUser("alice", "alicepass");

    const nonce = try auth.issueNonce();

    // Wrong password.
    const wrong = try clientResponse(
        std.testing.allocator,
        "alice",
        "wrongpass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
    );
    defer std.testing.allocator.free(wrong);
    try std.testing.expectError(error.BadResponse, auth.verifyRequest(authTestRequest(wrong)));

    // Unknown user.
    const ghost = try clientResponse(
        std.testing.allocator,
        "ghost",
        "nopass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
    );
    defer std.testing.allocator.free(ghost);
    try std.testing.expectError(error.UnknownUser, auth.verifyRequest(authTestRequest(ghost)));

    // Unknown nonce.
    const bad_nonce = try clientResponse(
        std.testing.allocator,
        "alice",
        "alicepass",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "REGISTER",
        "sip:pbx.local",
    );
    defer std.testing.allocator.free(bad_nonce);
    try std.testing.expectError(error.UnknownNonce, auth.verifyRequest(authTestRequest(bad_nonce)));

    // Missing header entirely.
    try std.testing.expectError(error.MissingCredentials, auth.verifyRequest(authTestRequest(null)));
}

test "verifyRequest reports stale nonces" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();
    try auth.addUser("alice", "alicepass");

    const nonce = try auth.issueNonce();

    // Backdate the nonce past its TTL without sleeping.
    const entry = auth.nonces.getPtr(nonce[0..]).?;
    entry.* = auth.nowSecs() - nonce_ttl_secs - 1;

    const header = try clientResponse(
        std.testing.allocator,
        "alice",
        "alicepass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
    );
    defer std.testing.allocator.free(header);
    try std.testing.expectError(error.StaleNonce, auth.verifyRequest(authTestRequest(header)));
    // Stale nonces are evicted on sight.
    try std.testing.expect(auth.nonces.get(nonce[0..]) == null);
}

test "issueNonce evicts past the cap" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();

    var i: usize = 0;
    while (i < max_nonces + 5) : (i += 1) {
        _ = try auth.issueNonce();
    }
    try std.testing.expect(auth.nonces.count() <= max_nonces);
}

test "addUser stores HA1 verifiers, never passwords" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();

    try auth.addUser("alice", "alicepass");
    const stored = auth.users.get("alice").?;
    // 16 raw bytes would fit a password; 32 hex chars can only be HA1.
    try std.testing.expect(stored.len == 32);
    try std.testing.expect(!std.mem.eql(u8, stored[0..], "alicepass"));
    const expected_ha1 = md5Hex(&.{ "alice", ":", realm, ":", "alicepass" });
    try std.testing.expectEqual(expected_ha1, stored);
}

test "verifyRequest round-trips a qop response" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();
    try auth.addUser("alice", "alicepass");

    const nonce = try auth.issueNonce();
    const header = try clientResponseQop(
        std.testing.allocator,
        "alice",
        "alicepass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
        "abcdef0123456789",
        "00000001",
    );
    defer std.testing.allocator.free(header);

    const username = try auth.verifyRequest(authTestRequest(header));
    try std.testing.expectEqualStrings("alice", username);
    // Single-use: the nonce is consumed, replay fails closed.
    try std.testing.expectError(error.UnknownNonce, auth.verifyRequest(authTestRequest(header)));
}

test "verifyRequest rejects qop tampering" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();
    try auth.addUser("alice", "alicepass");

    const nonce = try auth.issueNonce();
    const good = try clientResponseQop(
        std.testing.allocator,
        "alice",
        "alicepass",
        nonce[0..],
        "REGISTER",
        "sip:pbx.local",
        "abcdef0123456789",
        "00000001",
    );
    defer std.testing.allocator.free(good);

    // Wrong nc.
    const tampered_nc = try std.mem.replaceOwned(u8, std.testing.allocator, good, "nc=00000001", "nc=00000002");
    defer std.testing.allocator.free(tampered_nc);
    try std.testing.expectError(error.BadResponse, auth.verifyRequest(authTestRequest(tampered_nc)));

    // Unknown qop mode.
    const tampered_qop = try std.mem.replaceOwned(u8, std.testing.allocator, good, "qop=auth", "qop=auth-int");
    defer std.testing.allocator.free(tampered_qop);
    try std.testing.expectError(error.BadResponse, auth.verifyRequest(authTestRequest(tampered_qop)));

    // qop claimed but cnonce stripped.
    const stripped = try std.mem.replaceOwned(u8, std.testing.allocator, good, ", cnonce=\"abcdef0123456789\"", "");
    defer std.testing.allocator.free(stripped);
    try std.testing.expectError(error.BadResponse, auth.verifyRequest(authTestRequest(stripped)));
}

test "loadUsersData parses, skips junk, never retains passwords" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();

    const loaded = try auth.loadUsersData("test", "# comment\n" ++
        "\n" ++
        "alice:alicepass\r\n" ++
        "  bob  :  bobpass  \n" ++
        "no-separator-here\n" ++
        ":empty-user\n" ++
        "empty-pass:\n" ++
        "alice:newpass\n");
    // 3 good lines (alice twice — reload overwrites), 3 malformed skipped.
    try std.testing.expectEqual(@as(usize, 3), loaded);
    try std.testing.expectEqual(md5Hex(&.{ "alice", ":", realm, ":", "newpass" }), auth.users.get("alice").?);
    try std.testing.expectEqual(md5Hex(&.{ "bob", ":", realm, ":", "bobpass" }), auth.users.get("bob").?);
    try std.testing.expect(auth.users.count() == 2);
}

test "loadUsersFile round-trips through the filesystem" {
    const io = std.testing.io;
    var auth = Auth.init(std.testing.allocator, io);
    defer auth.deinit();

    const path = "test-users.tmp";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "carol:carolpass\n" });
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const loaded = try auth.loadUsersFile(path);
    try std.testing.expectEqual(@as(usize, 1), loaded);
    try std.testing.expectEqual(md5Hex(&.{ "carol", ":", realm, ":", "carolpass" }), auth.users.get("carol").?);

    // Missing file surfaces cleanly (main falls back to seeds on this).
    try std.testing.expectError(error.FileNotFound, auth.loadUsersFile("no-such-users-file"));
}
