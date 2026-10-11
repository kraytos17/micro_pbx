//! Call state machine and in-memory call context storage.

const std = @import("std");
const testing = std.testing;

const txn = @import("sip/transaction.zig");

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
    /// Re-INVITE leg headers, for rendering a 408 if the re-leg times out.
    /// invite_branch stays the ORIGINAL leg (Timer-B identity); these track
    /// the latest renegotiation attempt. Arena-owned, orphaned on supersede
    /// (reclaimed at teardown — bounded, documented).
    reinvite_via: ?[]u8 = null,
    reinvite_from: ?[]u8 = null,
    reinvite_to: ?[]u8 = null,
};

/// One dialog: call state plus its client transaction, sharing one arena
/// lifetime. Teardown frees everything at once (see removeCall); there are
/// no per-field frees to keep in sync.
pub const Dialog = struct {
    call: Call,
    invite_txn: ?txn.Transaction,
    arena: *std.heap.ArenaAllocator,

    /// Caches a final error response on the dialog transaction
    /// (arena-owned). Missing transactions are a silent no-op, mirroring
    /// storeResponse.
    pub fn storeInviteResponse(self: *Dialog, response: []const u8) !void {
        if (self.invite_txn) |*t| {
            t.response_buf = try self.arena.allocator().dupe(u8, response);
        }
    }

    /// Advances a dialog transaction to completed (Timer D wait).
    pub fn completeInviteTxn(self: *Dialog, now_ms: i64) void {
        if (self.invite_txn) |*t| {
            t.state = .completed;
            t.next_fire_at_ms = now_ms + txn.timer_d_ms;
        }
    }
};

/// Concurrent dialog cap (see TransactionLayer.max_transactions for the
/// server-cache twin). Bounds memory under INVITE floods. Tunable.
pub const max_dialogs: usize = 512;

/// Returns the dialog for call_id, creating it (or replacing a stale
/// terminated one left awaiting its BYE response). Creation past the cap
/// fails instead of growing unboundedly.
pub fn ensureDialog(
    calls: *std.StringHashMap(Dialog),
    allocator: std.mem.Allocator,
    call_id: []const u8,
    default: Call,
) !*Dialog {
    if (calls.getPtr(call_id)) |dlg| {
        if (dlg.call.state == .terminated) {
            removeCall(calls, allocator, call_id);
        } else {
            return dlg;
        }
    }

    const gop = try calls.getOrPut(call_id);
    // Reachable only on miss (hit returns above; eviction removes first),
    // but overwriting blindly would leak the arena on any logic slip.
    if (gop.found_existing) return gop.value_ptr;

    errdefer _ = calls.remove(call_id);
    gop.key_ptr.* = try allocator.dupe(u8, call_id);
    errdefer allocator.free(gop.key_ptr.*);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);

    arena.* = std.heap.ArenaAllocator.init(allocator);
    gop.value_ptr.* = .{ .call = default, .invite_txn = null, .arena = arena };
    return gop.value_ptr;
}

pub fn removeCall(
    calls: *std.StringHashMap(Dialog),
    allocator: std.mem.Allocator,
    call_id: []const u8,
) void {
    if (calls.fetchRemove(call_id)) |kv| {
        kv.value.arena.deinit();
        allocator.destroy(kv.value.arena);
        allocator.free(kv.key);
    }
}

/// Earliest pending dialog-transaction timeout (ms); Timer D default.
/// Considers both retransmit fires and Timer B lapses (see nextTimeout).
/// Pure scan for the run loop to min() against the server layer.
pub fn nextDialogTimeout(dialogs: *std.StringHashMap(Dialog), now_ms: i64) i64 {
    var min_timeout: i64 = txn.timer_d_ms;
    var it = dialogs.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.invite_txn) |*t| {
            if (t.state == .terminated) continue;
            const fire_in = t.next_fire_at_ms - now_ms;
            if (fire_in < min_timeout) min_timeout = fire_in;
            if (t.state == .trying) {
                const lapse_in = (t.created_at_ms + txn.timer_b_ms) - now_ms;
                if (lapse_in < min_timeout) min_timeout = lapse_in;
            }
        }
    }
    if (min_timeout < 0) min_timeout = 0;
    return min_timeout;
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

test "ensureDialog creates a dialog on miss" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    try testing.expect(calls.contains("call-id-123"));
    try std.testing.expect(dlg.call.caller_addr.ip4.port == 5060);
    try std.testing.expect(dlg.invite_txn == null);
}

test "ensureDialog returns the existing dialog on hit" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr1 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const caller_addr2 = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 200 }, .port = 5070 } };

    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr1 });
    dlg.call.state = .ringing;

    const again = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr2 });
    try testing.expect(again == dlg);
    try testing.expect(again.call.state == .ringing);
    try testing.expect(again.call.caller_addr.ip4.port == 5060);
}

test "ensureDialog replaces stale terminated dialogs" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    dlg.call.state = .terminated;

    const fresh = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    try std.testing.expect(fresh.call.state == .proceeding);
    try std.testing.expectEqual(@as(usize, 1), calls.count());
}

test "removeCall tears down the dialog arena" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    dlg.call.invite_branch = try dlg.arena.allocator().dupe(u8, "z9hG4bKabc123");
    try testing.expect(calls.contains("call-id-123"));

    removeCall(&calls, allocator, "call-id-123");
    try testing.expect(!calls.contains("call-id-123"));
}

test "dialog invite transaction store and complete" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });

    // Missing transactions are silent no-ops.
    try dlg.storeInviteResponse("SIP/2.0 200 OK\r\n\r\n");
    dlg.completeInviteTxn(1000);
    try std.testing.expect(dlg.invite_txn == null);

    // With a transaction: cache + Timer D arming.
    const t = try txn.makeTransaction(allocator, 1000, "z9hG4bKx", .INVITE, .invite, "INVITE x\r\n\r\n", caller_addr);
    dlg.invite_txn = t;
    try dlg.storeInviteResponse("SIP/2.0 486 Busy\r\n\r\n");
    try std.testing.expectEqualStrings("SIP/2.0 486 Busy\r\n\r\n", dlg.invite_txn.?.response_buf.?);
    // (Response buffer is arena-owned; the copy above borrows it.)
    dlg.completeInviteTxn(1000);
    try std.testing.expect(dlg.invite_txn.?.state == .completed);
    try std.testing.expectEqual(@as(i64, 1000 + txn.timer_d_ms), dlg.invite_txn.?.next_fire_at_ms);
}

test "nextDialogTimeout defaults and overdue" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    try std.testing.expectEqual(@as(i64, txn.timer_d_ms), nextDialogTimeout(&calls, 1000));

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    const dlg = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });
    dlg.invite_txn = try txn.makeTransaction(allocator, 1000, "z9hG4bKx", .INVITE, .invite, "INVITE x\r\n\r\n", caller_addr);
    dlg.invite_txn.?.next_fire_at_ms = 0;
    try std.testing.expectEqual(@as(i64, 0), nextDialogTimeout(&calls, 5000));

    // Terminated entries don't constrain the deadline.
    dlg.invite_txn.?.state = .terminated;
    try std.testing.expectEqual(@as(i64, txn.timer_d_ms), nextDialogTimeout(&calls, 5000));
}

test "ensureDialog keys by content, not pointer" {
    var alloc = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc.deinit();
    const allocator = alloc.allocator();

    var calls = std.StringHashMap(Dialog).init(allocator);
    defer calls.deinit();

    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    _ = try ensureDialog(&calls, allocator, "call-id-123", Call{ .caller_addr = caller_addr });

    const different_ptr = "call-id-123"; // different pointer, same content
    const again = try ensureDialog(&calls, allocator, different_ptr, Call{ .caller_addr = caller_addr });
    try std.testing.expectEqual(@as(usize, 1), calls.count());
    try testing.expect(again.call.caller_addr.ip4.port == 5060);
}
