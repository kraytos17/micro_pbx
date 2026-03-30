const std = @import("std");

pub const Contact = struct {
    address: std.Io.net.IpAddress,
    expires_at: i64,
    call_id: []u8,
    cseq: u32,
};

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

    pub fn register(self: *Registrar, aor: []const u8, contact: std.Io.net.IpAddress, expires: u32, call_id: []const u8, cseq: u32) !void {
        const now = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toSeconds();
        const expires_at = now + @as(i64, expires);
        if (self.map.getPtr(aor)) |entry| {
            if (std.mem.eql(u8, entry.call_id, call_id) and cseq <= entry.cseq) {
                return error.DuplicateCallId;
            }

            self.allocator.free(entry.call_id);
            entry.call_id = try self.allocator.dupe(u8, call_id);
            entry.address = contact;
            entry.expires_at = expires_at;
            entry.cseq = cseq;
        } else {
            const key_owned = try self.allocator.dupe(u8, aor);
            errdefer self.allocator.free(key_owned);
            const call_id_owned = try self.allocator.dupe(u8, call_id);
            errdefer self.allocator.free(call_id_owned);
            try self.map.put(key_owned, .{
                .address = contact,
                .expires_at = expires_at,
                .call_id = call_id_owned,
                .cseq = cseq,
            });
        }
    }

    pub fn lookup(self: *Registrar, aor: []const u8) ?Contact {
        const entry = self.map.get(aor) orelse return null;
        const now = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toSeconds();
        if (now > entry.expires_at) {
            _ = self.map.remove(aor);
            return null;
        }
        return entry;
    }

    pub fn unregister(self: *Registrar, aor: []const u8) void {
        if (self.map.fetchRemove(aor)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.call_id);
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
