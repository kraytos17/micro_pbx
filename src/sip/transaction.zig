//! SIP transaction layer: state tracking, retransmission, and response caching.

const std = @import("std");
const msg = @import("message.zig");
const Io = std.Io;
const net = std.Io.net;

// RFC 3261 SIP Timer Values (in milliseconds)
pub const t1_ms: u32 = 500; // RTT estimate
pub const t2_ms: u32 = 4000; // Maximum retransmit interval
pub const timer_b_ms: u32 = 32000; // INVITE client timeout
pub const timer_f_ms: u32 = 32000; // Non-INVITE client timeout
pub const timer_d_ms: u32 = 32000; // Wait time for response retransmit

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
    timer_b_fired: bool = false,
    timer_f_fired: bool = false,
};

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

    /// Creates an INVITE transaction for retransmission tracking.
    pub fn createInviteTransaction(
        self: *TransactionLayer,
        branch: []const u8,
        request_buf: []const u8,
        remote_addr: net.IpAddress,
    ) !void {
        const branch_owned = try self.allocator.dupe(u8, branch);
        errdefer self.allocator.free(branch_owned);

        const request_owned = try self.allocator.dupe(u8, request_buf);
        errdefer self.allocator.free(request_owned);

        const now_ms: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, 1000000));
        const txn_id: TransactionId = .{
            .branch = branch_owned,
            .method = .INVITE,
        };

        try self.map.put(txn_id, .{
            .id = txn_id,
            .state = .trying,
            .txn_type = .invite,
            .request_buf = request_owned,
            .response_buf = null,
            .remote_addr = remote_addr,
            .retransmit_count = 0,
            .next_fire_at_ms = now_ms + t1_ms,
            .t1_ms = t1_ms,
        });
    }

    pub fn createNonInviteTransaction(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
        request_buf: []const u8,
        remote_addr: net.IpAddress,
    ) !void {
        const branch_owned = try self.allocator.dupe(u8, branch);
        errdefer self.allocator.free(branch_owned);

        const request_owned = try self.allocator.dupe(u8, request_buf);
        errdefer self.allocator.free(request_owned);

        const now_ms: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, 1000000));
        const txn_id: TransactionId = .{
            .branch = branch_owned,
            .method = method,
        };

        try self.map.put(txn_id, .{
            .id = txn_id,
            .state = .trying,
            .txn_type = .non_invite,
            .request_buf = request_owned,
            .response_buf = null,
            .remote_addr = remote_addr,
            .retransmit_count = 0,
            .next_fire_at_ms = now_ms + t1_ms,
            .t1_ms = t1_ms,
        });
    }

    /// Caches a response on an existing transaction for retransmission replies.
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
    }

    pub fn setCompleted(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
    ) void {
        const id: TransactionId = .{
            .branch = branch,
            .method = method,
        };

        if (self.map.getPtr(id)) |entry| {
            entry.state = .completed;
            const now_ms: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, 1000000));
            if (entry.txn_type == .invite) {
                entry.next_fire_at_ms = now_ms + timer_d_ms;
            } else {
                entry.next_fire_at_ms = now_ms + timer_d_ms;
            }
        }
    }

    pub fn setTerminated(
        self: *TransactionLayer,
        branch: []const u8,
        method: msg.Method,
    ) void {
        const id: TransactionId = .{
            .branch = branch,
            .method = method,
        };

        if (self.map.getPtr(id)) |entry| {
            entry.state = .terminated;
        }
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

    /// Returns the time (ms) until the earliest pending transaction timeout.
    pub fn nextTimeout(self: *TransactionLayer) i64 {
        var min_timeout: i64 = timer_d_ms;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.state != .terminated) {
                const timeout = entry.value_ptr.next_fire_at_ms - @as(i64, @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, 1000000)));
                if (timeout < min_timeout) {
                    min_timeout = timeout;
                }
            }
        }
        if (min_timeout < 0) min_timeout = 0;
        return min_timeout;
    }

    /// Advances timers; returns the next request to retransmit, if any.
    pub fn tick(
        self: *TransactionLayer,
    ) ?struct { branch: []u8, method: msg.Method, data: []u8, addr: net.IpAddress } {
        const now_ms: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, 1000000));
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const txn = entry.value_ptr;
            if (txn.state == .terminated) continue;
            if (txn.state == .completed) {
                if (txn.txn_type == .invite) {
                    if (now_ms >= txn.next_fire_at_ms) {
                        entry.value_ptr.state = .terminated;
                        return null;
                    }
                } else {
                    if (now_ms >= txn.next_fire_at_ms) {
                        entry.value_ptr.state = .terminated;
                        return null;
                    }
                }
                continue;
            }
            if (now_ms >= txn.next_fire_at_ms) {
                if (txn.txn_type == .invite) {
                    if (txn.timer_b_fired) {
                        entry.value_ptr.state = .terminated;
                        return null;
                    }
                } else {
                    if (txn.timer_f_fired) {
                        entry.value_ptr.state = .terminated;
                        return null;
                    }
                }
                entry.value_ptr.retransmit_count += 1;

                const new_t1 = @min(txn.t1_ms * 2, t2_ms);
                entry.value_ptr.t1_ms = new_t1;
                entry.value_ptr.next_fire_at_ms = now_ms + new_t1;

                if (txn.txn_type == .invite and txn.retransmit_count >= 64) {
                    entry.value_ptr.timer_b_fired = true;
                } else if (txn.txn_type == .non_invite and txn.retransmit_count >= 64) {
                    entry.value_ptr.timer_f_fired = true;
                }

                return .{
                    .branch = entry.key_ptr.branch,
                    .method = txn.id.method,
                    .data = txn.request_buf,
                    .addr = txn.remote_addr,
                };
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

test "createInviteTransaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createInviteTransaction(branch, request, addr);

    try std.testing.expectEqual(@as(usize, 1), layer.map.count());
}

test "isRetransmission returns true for existing transaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createInviteTransaction(branch, request, addr);

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

    try layer.createInviteTransaction(branch, request, addr);
    try layer.storeResponse(branch, .INVITE, response);

    const txn = layer.getTransaction(branch, .INVITE);
    try std.testing.expect(txn != null);
    try std.testing.expect(txn.?.response_buf != null);
}

test "setCompleted and setTerminated" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createInviteTransaction(branch, request, addr);
    try std.testing.expectEqual(TransactionState.trying, layer.getTransaction(branch, .INVITE).?.state);

    layer.setCompleted(branch, .INVITE);
    try std.testing.expectEqual(TransactionState.completed, layer.getTransaction(branch, .INVITE).?.state);

    layer.setTerminated(branch, .INVITE);
    try std.testing.expectEqual(TransactionState.terminated, layer.getTransaction(branch, .INVITE).?.state);
}

test "removeTransaction" {
    const io = std.testing.io;
    var layer = TransactionLayer.init(std.testing.allocator, io);
    defer layer.deinit();

    const branch = "z9hG4bKtest";
    const request = "INVITE sip:test@pbx.local SIP/2.0\r\n\r\n";
    const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 100 }, .port = 5060 } };

    try layer.createInviteTransaction(branch, request, addr);
    try std.testing.expectEqual(@as(usize, 1), layer.map.count());

    layer.removeTransaction(branch, .INVITE);
    try std.testing.expectEqual(@as(usize, 0), layer.map.count());
}
