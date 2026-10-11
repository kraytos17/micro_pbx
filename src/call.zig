//! Call state machine and in-memory call context storage.

const std = @import("std");
const testing = std.testing;

const log = std.log.scoped(.call);

/// Lifecycle phases a SIP dialog moves through.
pub const CallState = enum {
    proceeding,
    ringing,
    answered,
    established,
    canceling,
    terminated,
};

/// Per-dialog context used to route ACK/BYE/CANCEL between caller and callee.
pub const Call = struct {
    state: CallState = .proceeding,
    caller_addr: std.Io.net.IpAddress,
    callee_contact_addr: ?std.Io.net.IpAddress = null,
    callee_resp_addr: ?std.Io.net.IpAddress = null,
    invite_branch: ?[]const u8 = null,
    /// Owned dupes of the original INVITE headers, for rendering a 408
    /// after the receive buffer is reused. Null until an INVITE is forwarded.
    caller_via: ?[]u8 = null,
    caller_from: ?[]u8 = null,
    caller_to: ?[]u8 = null,
    invite_cseq: u32 = 0,
};

pub fn removeCall(
    calls: *std.StringHashMap(Call),
    allocator: std.mem.Allocator,
    call_id: []const u8,
) void {
    if (calls.fetchRemove(call_id)) |kv| {
        allocator.free(kv.key);
        if (kv.value.invite_branch) |b| allocator.free(b);
        if (kv.value.caller_via) |v| allocator.free(v);
        if (kv.value.caller_from) |f| allocator.free(f);
        if (kv.value.caller_to) |t| allocator.free(t);
    }
}

pub fn putCall(
    calls: *std.StringHashMap(Call),
    allocator: std.mem.Allocator,
    call_id: []const u8,
    call: Call,
) !void {
    const gop = try calls.getOrPut(call_id);
    if (gop.found_existing) {
        gop.value_ptr.* = call;
    } else {
        errdefer _ = calls.remove(call_id);
        gop.key_ptr.* = try allocator.dupe(u8, call_id);
        gop.value_ptr.* = call;
    }
}

pub fn addressEqual(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    return std.Io.net.IpAddress.eql(&a, &b);
}

test "addressEqual returns true for same address" {
    const a = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const b = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    try testing.expect(addressEqual(a, b));
}

test "addressEqual returns false for different IP" {
    const a = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const b = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 101 }, .port = 5060 } };
    try testing.expect(!addressEqual(a, b));
}

test "addressEqual returns false for different port" {
    const a = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const b = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5061 } };
    try testing.expect(!addressEqual(a, b));
}

test "Call default state is proceeding" {
    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const call = Call{ .caller_addr = caller_addr };
    try testing.expect(call.state == .proceeding);
    try testing.expect(call.callee_contact_addr == null);
    try testing.expect(call.callee_resp_addr == null);
    try testing.expect(call.invite_branch == null);
}

test "CallState has all expected states" {
    try testing.expect(@as(u16, @backingInt(CallState.proceeding)) == 0);
    try testing.expect(@as(u16, @backingInt(CallState.ringing)) == 1);
    try testing.expect(@as(u16, @backingInt(CallState.answered)) == 2);
    try testing.expect(@as(u16, @backingInt(CallState.established)) == 3);
    try testing.expect(@as(u16, @backingInt(CallState.canceling)) == 4);
    try testing.expect(@as(u16, @backingInt(CallState.terminated)) == 5);
}

test "putCall inserts new call" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Call).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const call = Call{ .caller_addr = caller_addr };

    try putCall(&calls, allocator, "call-id-123", call);
    try testing.expect(calls.contains("call-id-123"));
    try testing.expect(calls.get("call-id-123").?.caller_addr.ip4.port == 5060);
}

test "putCall updates existing call" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Call).init(allocator);
    defer calls.deinit();

    const caller_addr1 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const caller_addr2 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 200 }, .port = 5070 } };

    try putCall(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr1 });
    try putCall(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr2, .state = .ringing });

    const entry = calls.get("call-id-123");
    try testing.expect(entry != null);
    try testing.expect(entry.?.caller_addr.ip4.port == 5070);
    try testing.expect(entry.?.state == .ringing);
}

test "removeCall removes call and frees memory" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Call).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try putCall(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    try testing.expect(calls.contains("call-id-123"));

    removeCall(&calls, allocator, "call-id-123");
    try testing.expect(!calls.contains("call-id-123"));
}

test "removeCall frees branch memory" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Call).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const branch = try allocator.dupe(u8, "z9hG4bKabc123");
    const call = Call{ .caller_addr = caller_addr, .invite_branch = branch };
    try putCall(&calls, allocator, "call-id-123", call);

    removeCall(&calls, allocator, "call-id-123");
    try testing.expect(!calls.contains("call-id-123"));
}

test "putCall handles different pointer but same content" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Call).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const call1 = Call{ .caller_addr = caller_addr };
    const call2 = Call{ .caller_addr = caller_addr, .state = .ringing };

    try putCall(&calls, allocator, "call-id-123", call1);

    const different_ptr = "call-id-123"; // different pointer, same content
    try putCall(&calls, allocator, different_ptr, call2);

    const entry = calls.get("call-id-123");
    try testing.expect(entry != null);
    try testing.expect(entry.?.state == .ringing);
}
