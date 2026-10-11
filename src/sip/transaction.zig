//! SIP transaction layer: state tracking, retransmission, and response caching.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const msg = @import("message.zig");

const log = std.log.scoped(.txn);

/// Current wall-clock time in milliseconds since the epoch.
fn nowMs(io: Io) i64 {
    return std.Io.Timestamp.now(io, std.Io.Clock.real).toMilliseconds();
}

// RFC 3261 SIP Timer Values (in milliseconds)
pub const t1_ms: u32 = 500; // RTT estimate
pub const t2_ms: u32 = 4000; // Maximum retransmit interval
pub const timer_b_ms: u32 = 32000; // INVITE client timeout
pub const timer_f_ms: u32 = 32000; // Non-INVITE client timeout
pub const timer_d_ms: u32 = 32000; // Wait time for response retransmit

// Bounds unauthenticated table growth (INVITE floods, 404/error caches).
// At the cap, creation fails and callers degrade gracefully; worst-case
// memory stays under ~2MB. Tunable.
pub const max_transactions: usize = 512;

/// Uniquely identifies a transaction by branch ID and method.
pub const TransactionId = struct {
    branch: []const u8,
    method: msg.Method,

    pub fn eql(a: TransactionId, b: TransactionId) bool {
        return std.mem.eql(u8, a.branch, b.branch) and a.method == b.method;
    }

    pub fn hash(self: TransactionId) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.branch);
        hasher.update(std.mem.asBytes(&self.method));
        return hasher.final();
    }
};

pub const TransactionIdContext = struct {
    pub fn hash(self: @This(), key: TransactionId) u64 {
        _ = self;
        return key.hash();
    }

    pub fn eql(self: @This(), a: TransactionId, b: TransactionId) bool {
        _ = self;
        return a.eql(b);
    }
};

/// Lifecycle phases of a SIP transaction.
pub const TransactionState = enum {
    trying,
    proceeding,
    completed,
    terminated,
};

/// Distinguishes retransmission/cleanup rules for INVITE vs non-INVITE.
pub const TransactionType = enum {
    invite,
    non_invite,
    cancelled,
};

/// Mutable per-transaction state: buffers, timers, and retransmission counters.
pub const Transaction = struct {
    id: TransactionId,
    state: TransactionState,
    txn_type: TransactionType,
    request_buf: []u8,
    response_buf: ?[]u8,
    remote_addr: net.IpAddress,
    retransmit_count: u8,
    next_fire_at_ms: i64,
    t1_ms: u32 = 500,
    /// Wall-clock creation time. Timer B/F fire at 64*T1 *elapsed* (RFC 3261
    /// §17.1.1.2/§17.1.2.2) — not after N retransmits, which backoff would
    /// stretch to minutes.
    created_at_ms: i64,
};

/// A single firing timer: the request bytes to resend and where to send them.
/// Slices borrow map memory; resend before any mutation or removal.
pub const Retransmission = struct {
    branch: []const u8,
    method: msg.Method,
    data: []u8,
    addr: net.IpAddress,
};

/// One timer event from tick(): either a request to retransmit or an
/// expired (Timer B/F) transaction. Payloads borrow map memory; act on
/// them before any mutation or removal (same discipline as Retransmission).
pub const TickEvent = union(enum) {
    retransmit: Retransmission,
    expired: TransactionId,
};

/// Builds a transaction value, duping buffers into `alloc` (heap for the
/// server cache, dialog arena for client legs). Pure apart from allocation.
pub fn makeTransaction(
    alloc: std.mem.Allocator,
    now_ms: i64,
    branch: []const u8,
    method: msg.Method,
    txn_type: TransactionType,
    request_buf: []const u8,
    remote_addr: net.IpAddress,
) !Transaction {
    const branch_owned = try alloc.dupe(u8, branch);
    errdefer alloc.free(branch_owned);

    const request_owned = try alloc.dupe(u8, request_buf);
    errdefer alloc.free(request_owned);
    return .{
        .id = .{ .branch = branch_owned, .method = method },
        .state = .trying,
        .txn_type = txn_type,
        .request_buf = request_owned,
        .response_buf = null,
        .remote_addr = remote_addr,
        .retransmit_count = 0,
        .next_fire_at_ms = now_ms + t1_ms,
        .t1_ms = t1_ms,
        .created_at_ms = now_ms,
    };
}

/// Advances a single transaction; returns its timer event, if any.
/// Shared by the server-map driver below and dialog-scoped timer passes.
/// Returned slices borrow the transaction: act before mutating it.
pub fn tickOne(now_ms: i64, id: TransactionId, txn: *Transaction) ?TickEvent {
    if (txn.state == .terminated) return null;
    if (txn.state == .completed) {
        if (now_ms >= txn.next_fire_at_ms) {
            txn.state = .terminated;
        }
        return null;
    }
    // Timer B/F lapse ends the transaction regardless of schedule: with
    // capped backoff the next retransmit can sit past the 64*T1 deadline.
    const timeout_ms: i64 = if (txn.txn_type == .invite) timer_b_ms else timer_f_ms;
    if (now_ms - txn.created_at_ms >= timeout_ms) {
        txn.state = .terminated;
        return .{ .expired = id };
    }
    if (now_ms < txn.next_fire_at_ms) return null;

    txn.retransmit_count += 1;
    const new_t1 = @min(txn.t1_ms * 2, t2_ms);

    txn.t1_ms = new_t1;
    txn.next_fire_at_ms = now_ms + new_t1;

    return .{ .retransmit = .{
        .branch = txn.id.branch,
        .method = txn.id.method,
        .data = txn.request_buf,
        .addr = txn.remote_addr,
    } };
}

/// Drives timer-driven retransmission and response caching for all transactions.
pub const TransactionLayer = struct {
    map: std.HashMap(TransactionId, Transaction, TransactionIdContext, 80),
    allocator: std.mem.Allocator,
    io: Io,

    pub fn init(allocator: std.mem.Allocator, io: Io) TransactionLayer {
        return .{
            .map = std.HashMap(TransactionId, Transaction, TransactionIdContext, 80).init(allocator),
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *TransactionLayer) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.branch);
            self.allocator.free(entry.value_ptr.request_buf);
            if (entry.value_ptr.response_buf) |resp| {
                self.allocator.free(resp);
            }
        }
        self.map.deinit();
    }

    pub fn isRetransmission(self: *TransactionLayer, id: TransactionId) bool {
        return self.map.contains(id);
    }

    pub fn createNonInviteTransaction(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
        request_buf: []const u8,
        remote_addr: net.IpAddress,
    ) !void {
        if (self.map.count() >= max_transactions) return error.TransactionTableFull;

        const t = try makeTransaction(self.allocator, nowMs(self.io), branch, method, .non_invite, request_buf, remote_addr);
        try self.map.put(t.id, t);
    }

    /// Caches a response on an existing transaction for retransmission replies.
    /// Marks the entry completed with a Timer-D deadline: cache entries are
    /// server-side answer records, not client transactions — leaving them
    /// trying would spontaneously retransmit the cached response on backoff
    /// schedule (a stale 404 arriving mid-suite killed a strict wait once).
    /// Replay reads response_buf regardless of state (isRetransmission is
    /// map membership), so caching behavior is unchanged.
    pub fn storeResponse(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
        response_buf: []const u8,
    ) !void {
        const id: TransactionId = .{
            .branch = branch,
            .method = method,
        };

        const entry = self.map.getPtr(id) orelse return;
        if (entry.response_buf) |existing| {
            self.allocator.free(existing);
        }

        entry.response_buf = try self.allocator.dupe(u8, response_buf);
        entry.state = .completed;
        entry.next_fire_at_ms = nowMs(self.io) + timer_d_ms;
    }

    pub fn getTransaction(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
    ) ?*Transaction {
        const id: TransactionId = .{
            .branch = branch,
            .method = method,
        };
        return self.map.getPtr(id);
    }

    /// Returns the time (ms) until the earliest pending transaction timeout:
    /// either the next retransmit fire or a Timer B/F/D lapse, whichever
    /// comes first. Without the lapse term, capped backoff could sleep past
    /// a 32s deadline by up to T2 (4s).
    pub fn nextTimeout(self: *TransactionLayer) i64 {
        var min_timeout: i64 = timer_d_ms;
        const now_ms = nowMs(self.io);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const txn = entry.value_ptr;
            if (txn.state == .terminated) continue;
            const fire_in = txn.next_fire_at_ms - now_ms;
            if (fire_in < min_timeout) min_timeout = fire_in;
            if (txn.state == .trying) {
                const lapse_ms: i64 = if (txn.txn_type == .invite) timer_b_ms else timer_f_ms;
                const lapse_in = (txn.created_at_ms + lapse_ms) - now_ms;
                if (lapse_in < min_timeout) min_timeout = lapse_in;
            }
        }
        if (min_timeout < 0) min_timeout = 0;
        return min_timeout;
    }

    /// Advances timers; returns the next timer event, if any.
    /// Thin driver over tickOne; dialog-scoped passes share the step.
    pub fn tick(
        self: *TransactionLayer,
    ) ?TickEvent {
        const now_ms = nowMs(self.io);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (tickOne(now_ms, entry.key_ptr.*, entry.value_ptr)) |ev| {
                return ev;
            }
        }
        return null;
    }

    pub fn removeTransaction(self: *TransactionLayer, branch: []const u8, method: msg.Method) void {
        const id: TransactionId = .{
            .branch = branch,
            .method = method,
        };
        if (self.map.fetchRemove(id)) |kv| {
            self.allocator.free(kv.key.branch);
            self.allocator.free(kv.value.request_buf);
            if (kv.value.response_buf) |resp| {
                self.allocator.free(resp);
            }
        }
    }

    /// Removes all terminated transactions, freeing their buffers.
    /// Collects keys first so removal never runs mid-iteration.
    pub fn sweepTerminated(self: *TransactionLayer) !void {
        var dead: std.ArrayList(TransactionId) = .empty;
        defer dead.deinit(self.allocator);

        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.state == .terminated) {
                try dead.append(self.allocator, entry.key_ptr.*);
            }
        }
        for (dead.items) |id| {
            self.removeTransaction(id.branch, id.method);
        }
    }
};

test "TransactionId eql" {
    const id1: TransactionId = .{ .branch = "z9hG4bKabc", .method = .INVITE };
    const id2: TransactionId = .{ .branch = "z9hG4bKabc", .method = .INVITE };
    const id3: TransactionId = .{ .branch = "z9hG4bKdef", .method = .INVITE };
    const id4: TransactionId = .{ .branch = "z9hG4bKabc", .method = .REGISTER };

    try std.testing.expect(id1.eql(id2));
    try std.testing.expect(!id1.eql(id3));
    try std.testing.expect(!id1.eql(id4));
}

test "TransactionLayer init and deinit" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    try std.testing.expectEqual(@as(usize, 0), layer.map.count());
}

test "createNonInviteTransaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);

    try std.testing.expectEqual(@as(usize, 1), layer.map.count());
}

test "isRetransmission returns true for existing transaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);

    const id: TransactionId = .{ .branch = branch, .method = .INVITE };
    try std.testing.expect(layer.isRetransmission(id));
}

test "isRetransmission returns false for non-existing transaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const id: TransactionId = .{ .branch = "z9hG4bKnothere", .method = .INVITE };
    try std.testing.expect(!layer.isRetransmission(id));
}

test "storeResponse and getTransaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const response = "SIP/2.0 180 Ringing\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    try layer.storeResponse(branch, .INVITE, response);

    const txn = layer.getTransaction(branch, .INVITE);
    try std.testing.expect(txn != null);
    try std.testing.expect(txn.?.response_buf != null);
}

test "removeTransaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    try std.testing.expectEqual(@as(usize, 1), layer.map.count());

    layer.removeTransaction(branch, .INVITE);
    try std.testing.expectEqual(@as(usize, 0), layer.map.count());
}

test "tick retransmits overdue invite transaction with backoff" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtick";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    // Force the timer overdue without real sleeping.
    layer.getTransaction(branch, .INVITE).?.next_fire_at_ms = 0;

    const fired = layer.tick();
    try std.testing.expect(fired != null);
    const r = fired.?.retransmit;
    try std.testing.expectEqualStrings(request, r.data);
    try std.testing.expectEqual(addr, r.addr);

    const txn = layer.getTransaction(branch, .INVITE).?;
    try std.testing.expectEqual(@as(u8, 1), txn.retransmit_count);
    try std.testing.expectEqual(@as(u32, 1000), txn.t1_ms);
}

test "tick caps backoff at T2" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKcap";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    const txn = layer.getTransaction(branch, .INVITE).?;
    txn.t1_ms = t2_ms;
    txn.next_fire_at_ms = 0;

    const fired = layer.tick();
    try std.testing.expect(fired != null);
    try std.testing.expectEqual(t2_ms, layer.getTransaction(branch, .INVITE).?.t1_ms);
}

test "tick terminates invite transaction after Timer B" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtimerb";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    // Invite-typed entry via makeTransaction (createInviteTransaction is gone;
    // only the dialog path creates client transactions now). Creation time
    // is real: Timer B must be far off for the first half of the test.
    const now_ms = std.Io.Timestamp.now(io, std.Io.Clock.real).toMilliseconds();
    var t = try makeTransaction(std.testing.allocator, now_ms, branch, .INVITE, .invite, request, addr);
    t.next_fire_at_ms = 0;
    try layer.map.put(t.id, t);

    // Fresh transaction retransmits while Timer B is far off.
    const fired = layer.tick();
    try std.testing.expect(fired != null);
    try std.testing.expect(fired.? == .retransmit);

    // Backdate creation past 64*T1: the next fire expires instead.
    const txn = layer.getTransaction(branch, .INVITE).?;
    txn.created_at_ms = now_ms - timer_b_ms - 1;
    txn.next_fire_at_ms = 0;
    const expired = layer.tick();
    try std.testing.expect(expired != null);
    const id = expired.?.expired;
    try std.testing.expectEqualStrings(branch, id.branch);
    try std.testing.expectEqual(msg.Method.INVITE, id.method);
    try std.testing.expectEqual(TransactionState.terminated, layer.getTransaction(branch, .INVITE).?.state);
}

test "nextTimeout defaults to Timer D when empty, zero when overdue" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    try std.testing.expectEqual(@as(i64, timer_d_ms), layer.nextTimeout());

    const branch = "z9hG4bKnto";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    layer.getTransaction(branch, .INVITE).?.next_fire_at_ms = 0;
    try std.testing.expectEqual(@as(i64, 0), layer.nextTimeout());
}

test "nextTimeout surfaces a lapsed Timer B ahead of schedule" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKlapsed";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction(branch, .INVITE, request, addr);
    const txn = layer.getTransaction(branch, .INVITE).?;
    // Retransmit scheduled far out, but Timer B already lapsed: the
    // deadline must win so expiry isn't delayed a full backoff interval.
    txn.next_fire_at_ms = std.Io.Timestamp.now(io, std.Io.Clock.real).toMilliseconds() + 4000;
    txn.created_at_ms = std.Io.Timestamp.now(io, std.Io.Clock.real).toMilliseconds() - timer_b_ms - 1;
    try std.testing.expectEqual(@as(i64, 0), layer.nextTimeout());
}

test "sweepTerminated removes only terminated transactions" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createNonInviteTransaction("z9hG4bKdead", .INVITE, "INVITE sip:a@pbx.local SIP/2.0\r\n\r\n", addr);
    try layer.createNonInviteTransaction("z9hG4bKlive", .INVITE, "INVITE sip:b@pbx.local SIP/2.0\r\n\r\n", addr);
    try std.testing.expectEqual(@as(usize, 2), layer.map.count());

    layer.getTransaction("z9hG4bKdead", .INVITE).?.state = .terminated;
    try layer.sweepTerminated();

    try std.testing.expectEqual(@as(usize, 1), layer.map.count());
    try std.testing.expect(layer.getTransaction("z9hG4bKdead", .INVITE) == null);
    try std.testing.expect(layer.getTransaction("z9hG4bKlive", .INVITE) != null);
}

test "createNonInviteTransaction enforces the table cap" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };
    var i: usize = 0;
    while (i < max_transactions) : (i += 1) {
        var branch_buf: [32]u8 = undefined;
        const branch = std.fmt.bufPrint(&branch_buf, "z9hG4bK{d}", .{i}) catch unreachable;
        try layer.createNonInviteTransaction(branch, .INVITE, "INVITE sip:x@y SIP/2.0\r\n\r\n", addr);
    }
    try std.testing.expectEqual(max_transactions, layer.map.count());
    try std.testing.expectError(
        error.TransactionTableFull,
        layer.createNonInviteTransaction("z9hG4bKoverflow", .INVITE, "INVITE sip:x@y SIP/2.0\r\n\r\n", addr),
    );
}
