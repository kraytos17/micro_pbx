//! User registration store with dual-key AOR lookup (username and username@domain).

const std = @import("std");

const log = std.log.scoped(.registrar);

/// Returns the username portion of an AOR, or null if it lacks a `sip:` prefix.
pub fn extractUsername(aor: []const u8) ?[]const u8 {
    const sip_prefix = "sip:";
    if (!std.mem.startsWith(u8, aor, sip_prefix)) {
        return null;
    }

    const after_sip = aor[sip_prefix.len..];
    const at_pos = std.mem.find(u8, after_sip, "@") orelse {
        return after_sip;
    };
    return after_sip[0..at_pos];
}

pub const Contact = struct {
    address: std.Io.net.IpAddress,
    expires_at: i64,
    call_id: []u8,
    cseq: u32,
};

/// In-memory registration store keyed by AOR.
pub const Registrar = struct {
    map: std.StringHashMap(Contact),
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Registrar {
        return .{
            .map = std.StringHashMap(Contact).init(allocator),
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *Registrar) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.call_id);
        }
        self.map.deinit();
    }

    /// Registers (or refreshes) a contact under the AOR and its username-only key.
    pub fn register(
        self: *Registrar,
        aor: []const u8,
        contact: std.Io.net.IpAddress,
        expires: u32,
        call_id: []const u8,
        cseq: u32,
    ) !void {
        const now = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toSeconds();
        const expires_at = now + @as(i64, expires);
        const gop = try self.map.getOrPut(aor);
        if (gop.found_existing) {
            const entry = gop.value_ptr;
            if (std.mem.eql(u8, entry.call_id, call_id) and cseq <= entry.cseq) {
                return error.DuplicateCallId;
            }

            self.allocator.free(entry.call_id);
            entry.call_id = try self.allocator.dupe(u8, call_id);
            entry.address = contact;
            entry.expires_at = expires_at;
            entry.cseq = cseq;
        } else {
            errdefer _ = self.map.remove(aor);
            gop.key_ptr.* = try self.allocator.dupe(u8, aor);
            errdefer self.allocator.free(gop.key_ptr.*);
            gop.value_ptr.* = .{
                .address = contact,
                .expires_at = expires_at,
                .call_id = try self.allocator.dupe(u8, call_id),
                .cseq = cseq,
            };
        }

        if (extractUsername(aor)) |username| {
            const username_key = try self.allocator.print("sip:{s}", .{username});
            const ugop = try self.map.getOrPut(username_key);
            if (ugop.found_existing) {
                self.allocator.free(username_key);
                const entry = ugop.value_ptr;
                self.allocator.free(entry.call_id);
                entry.call_id = try self.allocator.dupe(u8, call_id);
                entry.address = contact;
                entry.expires_at = expires_at;
                entry.cseq = cseq;
            } else {
                errdefer {
                    _ = self.map.remove(username_key);
                    self.allocator.free(username_key);
                }

                ugop.key_ptr.* = username_key;
                ugop.value_ptr.* = .{
                    .address = contact,
                    .expires_at = expires_at,
                    .call_id = try self.allocator.dupe(u8, call_id),
                    .cseq = cseq,
                };
            }
        }
    }

    /// Looks up a contact by exact AOR, falling back to username-only match.
    pub fn lookup(self: *Registrar, aor: []const u8) ?Contact {
        const now = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toSeconds();
        if (self.map.get(aor)) |entry| {
            if (now > entry.expires_at) {
                if (self.map.fetchRemove(aor)) |kv| {
                    self.allocator.free(kv.key);
                    self.allocator.free(kv.value.call_id);
                }
                return null;
            }
            return entry;
        }
        if (extractUsername(aor)) |username| {
            const username_key = self.allocator.print("sip:{s}", .{username}) catch return null;
            defer self.allocator.free(username_key);

            if (self.map.get(username_key)) |entry| {
                if (now > entry.expires_at) {
                    if (self.map.fetchRemove(username_key)) |kv| {
                        self.allocator.free(kv.key);
                        self.allocator.free(kv.value.call_id);
                    }
                    return null;
                }
                return entry;
            }
        }
        return null;
    }

    pub fn unregister(self: *Registrar, aor: []const u8) void {
        if (self.map.fetchRemove(aor)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.call_id);
        }
        if (extractUsername(aor)) |username| {
            const username_key = self.allocator.print("sip:{s}", .{username}) catch return;
            defer self.allocator.free(username_key);
            if (self.map.fetchRemove(username_key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.call_id);
            }
        }
    }
};

test "register and lookup" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };
    try registrar.register("sip:alice@pbx.local", addr, 3600, "callid1", 1);

    const found = registrar.lookup("sip:alice@pbx.local");
    try std.testing.expect(found != null);
}

test "lookup returns null for unknown AOR" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();
    try std.testing.expect(registrar.lookup("sip:nobody@pbx.local") == null);
}

test "register refresh updates existing contact" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr1 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };
    const addr2 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5060 } };

    try registrar.register("sip:alice@pbx.local", addr1, 3600, "callid1", 1);
    try registrar.register("sip:alice@pbx.local", addr2, 3600, "callid2", 2);

    const found = registrar.lookup("sip:alice@pbx.local");
    try std.testing.expect(found != null);
    try std.testing.expectEqual(addr2, found.?.address);
    try std.testing.expectEqual(@as(u32, 2), found.?.cseq);
}

test "unregister removes contact" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };
    try registrar.register("sip:alice@pbx.local", addr, 3600, "callid1", 1);

    registrar.unregister("sip:alice@pbx.local");

    const found = registrar.lookup("sip:alice@pbx.local");
    try std.testing.expect(found == null);
}

test "duplicate callid with lower cseq is rejected" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };
    try registrar.register("sip:alice@pbx.local", addr, 3600, "callid1", 5);

    const result = registrar.register("sip:alice@pbx.local", addr, 3600, "callid1", 3);
    try std.testing.expectError(error.DuplicateCallId, result);
}

test "register multiple users" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr1 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };
    const addr2 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5060 } };
    const addr3 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 15 }, .port = 5060 } };

    try registrar.register("sip:alice@pbx.local", addr1, 3600, "call1", 1);
    try registrar.register("sip:bob@pbx.local", addr2, 3600, "call2", 1);
    try registrar.register("sip:charlie@pbx.local", addr3, 3600, "call3", 1);

    try std.testing.expect(registrar.lookup("sip:alice@pbx.local") != null);
    try std.testing.expect(registrar.lookup("sip:bob@pbx.local") != null);
    try std.testing.expect(registrar.lookup("sip:charlie@pbx.local") != null);
    try std.testing.expect(registrar.lookup("sip:dave@pbx.local") == null);
}

test "lookup by username works across different domains" {
    const io = std.testing.io;
    var registrar = Registrar.init(std.testing.allocator, io);
    defer registrar.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 5 }, .port = 5060 } };

    try registrar.register("sip:alice@pbx.local", addr, 3600, "callid1", 1);
    const found1 = registrar.lookup("sip:alice@127.0.0.1:5060");
    try std.testing.expect(found1 != null);
    try std.testing.expectEqual(addr, found1.?.address);

    const found2 = registrar.lookup("sip:alice");
    try std.testing.expect(found2 != null);
    try std.testing.expectEqual(addr, found2.?.address);
}
