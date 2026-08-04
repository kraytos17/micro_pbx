//! Stateful PBX core: owns call table, transactions, RTP sessions, and dispatch.

const std = @import("std");
const transport = @import("transport.zig");
const msg = @import("sip/message.zig");
const parser = @import("sip/parser.zig");
const registrar = @import("registrar.zig");
const proxy = @import("proxy.zig");
const rtp = @import("rtp.zig");
const call = @import("call.zig");
const txn = @import("sip/transaction.zig");

const log = std.log.scoped(.main);

/// A running PBX server: owns all mutable state and the dispatch loop.
pub const Pbx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: transport.UdpSocket,
    reg: registrar.Registrar,
    txn_layer: txn.TransactionLayer,
    calls: std.StringHashMap(call.Call),
    rtp_sessions: rtp.Sessions,
    rtp_sockets: std.ArrayList(transport.UdpSocket),
    pbx_addr: std.Io.net.IpAddress,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16) !Pbx {
        var self = Pbx{
            .allocator = allocator,
            .io = io,
            .socket = try transport.UdpSocket.init(io, port),
            .reg = registrar.Registrar.init(allocator, io),
            .txn_layer = txn.TransactionLayer.init(allocator, io),
            .calls = std.StringHashMap(call.Call).init(allocator),
            .rtp_sessions = rtp.Sessions.init(allocator),
            .rtp_sockets = std.ArrayList(transport.UdpSocket).initCapacity(allocator, 32) catch unreachable,
            .pbx_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = port } },
        };
        errdefer self.deinit();
        return self;
    }

    pub fn deinit(self: *Pbx) void {
        self.socket.deinit();
        self.reg.deinit();
        self.txn_layer.deinit();

        var it = self.calls.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            if (kv.value_ptr.*.invite_branch) |b| self.allocator.free(b);
        }

        self.calls.deinit();
        self.rtp_sessions.deinit();
        for (self.rtp_sockets.items) |*sock| {
            sock.deinit();
        }
        self.rtp_sockets.deinit(self.allocator);
    }

    /// Main event loop: drains RTP sockets, then blocks on the SIP socket.
    pub fn run(self: *Pbx) !void {
        var recv_buf: [4096]u8 = undefined;
        var resp_buf: [4096]u8 = undefined;
        var fwd_buf: [4096]u8 = undefined;
        var rtp_buf: [2048]u8 = undefined;

        while (true) {
            for (self.rtp_sockets.items) |*rtp_sock| {
                const result = rtp_sock.recvFrom(&rtp_buf) catch continue;
                rtp.handleRtpPacket(result.data, result.from, &self.rtp_sessions, &self.socket) catch continue;
            }

            const result = self.socket.recvFrom(&recv_buf) catch |err| {
                log.err("recvFrom error: {}", .{err});
                continue;
            };

            log.debug("--- Received {} bytes ---", .{result.data.len});
            const message = parser.parse(result.data) catch |err| {
                log.warn("parse error: {}", .{err});
                continue;
            };

            switch (message) {
                .request => |req| {
                    log.debug("SIP REQUEST: {s} to {s}", .{ req.method.toSlice(), req.request_uri });
                    log.info("{s} {s} call-id={s}", .{ req.method.toSlice(), req.request_uri, req.call_id });
                    switch (req.method) {
                        .REGISTER => self.onRegister(req, result.from, &resp_buf) catch |err| {
                            log.err("handleRegister error: {}", .{err});
                        },
                        .INVITE => self.onInvite(req, result.from, &resp_buf, &fwd_buf) catch |err| {
                            log.err("handleInvite error: {}", .{err});
                        },
                        .ACK => self.onAck(req, result.from, &fwd_buf) catch |err| {
                            log.err("handleAck error: {}", .{err});
                        },
                        .BYE => self.onBye(req, result.from, &fwd_buf) catch |err| {
                            log.err("handleBye error: {}", .{err});
                        },
                        .MESSAGE => self.onMessage(req, result.from, &resp_buf, &fwd_buf) catch |err| {
                            log.err("handleMessage error: {}", .{err});
                        },
                        .OPTIONS => self.onOptions(req, result.from, &resp_buf, &recv_buf) catch |err| {
                            log.err("handleOptions error: {}", .{err});
                        },
                        .CANCEL => self.onCancel(req, result.from, &resp_buf, &fwd_buf) catch |err| {
                            log.err("handleCancel error: {}", .{err});
                        },
                    }
                },
                .response => |resp| self.handleResponse(resp, result.data, result.from, &fwd_buf),
            }
        }
    }

    fn onRegister(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        resp_buf: []u8,
    ) !void {
        try proxy.handleRegister(req, from, &self.reg, &self.socket, resp_buf);
    }

    fn onInvite(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        resp_buf: []u8,
        fwd_buf: []u8,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        const txn_id: txn.TransactionId = .{ .branch = req.via_branch, .method = .INVITE };
        if (self.txn_layer.isRetransmission(txn_id)) {
            log.info("INVITE retransmission detected for branch {s}", .{req.via_branch});
            if (self.txn_layer.getTransaction(req.via_branch, .INVITE)) |existing_txn| {
                if (existing_txn.response_buf) |cached_resp| {
                    try self.socket.sendTo(cached_resp, from);
                    return;
                }
            }
        }

        var call_ctx: call.Call = if (self.calls.get(req.call_id)) |existing| existing else .{ .caller_addr = from };

        try call.putCall(&self.calls, self.allocator, req.call_id, call_ctx);
        if (call_ctx.state == .proceeding and call_ctx.callee_contact_addr == null) {
            const dest_aor = proxy.extractUri(req.request_uri);
            const contact = self.reg.lookup(dest_aor) orelse {
                log.warn("INVITE {s} not found, sending 404", .{dest_aor});
                // Generate branch for 404 response (RFC 3261)
                const branch_404 = try proxy.generateBranch(self.allocator, self.io);
                defer self.allocator.free(branch_404);

                // Build 404 response
                var response_buf: [2048]u8 = undefined;
                const response_404 = try proxy.buildResponse(&response_buf, 404, "Not Found", req, branch_404);

                // Send the 404
                try proxy.sendResponseWithBranch(&self.socket, from, resp_buf, 404, "Not Found", req, branch_404);

                // Cache the 404 response for retransmissions using client's branch
                try self.txn_layer.createNonInviteTransaction(req.via_branch, .INVITE, response_404, from);
                try self.txn_layer.storeResponse(req.via_branch, .INVITE, response_404);

                return;
            };

            call_ctx.callee_contact_addr = contact.address;

            const invite_result = try proxy.handleInvite(req, from, contact, &self.socket, self.pbx_addr, resp_buf, fwd_buf, arena.allocator(), self.io);

            try self.txn_layer.createInviteTransaction(invite_result.branch, invite_result.forwarded, contact.address);

            if (call_ctx.invite_branch) |old| self.allocator.free(old);
            call_ctx.invite_branch = self.allocator.dupe(u8, invite_result.branch) catch null;
            arena.allocator().free(invite_result.branch);
            try call.putCall(&self.calls, self.allocator, req.call_id, call_ctx);
        } else {
            try proxy.sendResponse(&self.socket, from, resp_buf, 100, "Trying", req);
        }
    }

    fn onAck(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        fwd_buf: []u8,
    ) !void {
        if (self.calls.getPtr(req.call_id)) |call_ctx| {
            if (call_ctx.state == .answered) {
                call_ctx.state = .established;
                log.info("call {s} established", .{req.call_id});
            }

            const dest_addr = call_ctx.callee_contact_addr orelse call_ctx.caller_addr;
            const branch = try proxy.generateBranch(self.allocator, self.io);
            defer self.allocator.free(branch);
            proxy.handleAck(req, dest_addr, &self.reg, &self.socket, self.pbx_addr, branch, fwd_buf) catch |err| {
                log.err("handleAck error: {}", .{err});
            };

            if (self.rtp_sessions.getSession(req.call_id)) |session| {
                const caller_socket = try transport.UdpSocket.init(self.io, session.caller_rtp_port);
                try self.rtp_sockets.append(self.allocator, caller_socket);
                const callee_socket = try transport.UdpSocket.init(self.io, session.callee_rtp_port);
                try self.rtp_sockets.append(self.allocator, callee_socket);
            }
        } else {
            const branch = try proxy.generateBranch(self.allocator, self.io);
            defer self.allocator.free(branch);
            proxy.handleAck(req, from, &self.reg, &self.socket, self.pbx_addr, branch, fwd_buf) catch |err| {
                log.err("handleAck error: {}", .{err});
            };
        }
    }

    fn onBye(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        fwd_buf: []u8,
    ) !void {
        const branch = try proxy.generateBranch(self.allocator, self.io);
        defer self.allocator.free(branch);

        if (self.calls.getPtr(req.call_id)) |call_ctx| {
            const is_from_caller = call.addressEqual(from, call_ctx.caller_addr);
            const dest_addr = if (is_from_caller)
                call_ctx.callee_contact_addr orelse from
            else
                call_ctx.caller_addr;

            call_ctx.state = .terminated;
            log.info("call {s} terminated (BYE)", .{req.call_id});
            proxy.handleBye(req, dest_addr, &self.reg, &self.socket, self.pbx_addr, branch, fwd_buf) catch |err| {
                log.err("handleBye error: {}", .{err});
            };
            call.removeCall(&self.calls, self.allocator, req.call_id);
            self.rtp_sessions.removeSession(req.call_id);
        } else {
            proxy.sendResponse(&self.socket, from, fwd_buf, 481, "Call Leg Does Not Exist", req) catch {};
        }
    }

    fn onMessage(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        resp_buf: []u8,
        fwd_buf: []u8,
    ) !void {
        try proxy.handleMessage(req, from, &self.reg, &self.socket, resp_buf, fwd_buf);
    }

    fn onOptions(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        resp_buf: []u8,
        fwd_buf: []u8,
    ) !void {
        try proxy.handleOptions(req, from, &self.reg, &self.socket, resp_buf, fwd_buf);
    }

    fn onCancel(
        self: *Pbx,
        req: msg.Request,
        from: std.Io.net.IpAddress,
        resp_buf: []u8,
        fwd_buf: []u8,
    ) !void {
        if (self.calls.getPtr(req.call_id)) |call_ctx| {
            if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                call_ctx.state = .canceling;
                log.info("call {s} canceling", .{req.call_id});
                const callee = call_ctx.callee_contact_addr orelse {
                    log.warn("CANCEL for call with no callee_contact_addr", .{});
                    return;
                };

                const branch = call_ctx.invite_branch orelse {
                    log.warn("CANCEL for call with no stored invite_branch", .{});
                    return;
                };

                proxy.handleCancel(req, from, callee, self.pbx_addr, branch, &self.socket, resp_buf, fwd_buf) catch |err| {
                    log.err("handleCancel error: {}", .{err});
                };
            } else {
                proxy.sendResponse(&self.socket, from, resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
            }
        } else {
            proxy.sendResponse(&self.socket, from, resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
        }
    }

    fn handleResponse(
        self: *Pbx,
        resp: msg.Response,
        data: []u8,
        from: std.Io.net.IpAddress,
        fwd_buf: []u8,
    ) void {
        log.debug("SIP RESPONSE: {} {s}", .{ resp.status_code, resp.reason_phrase });
        const dest_addr = if (self.calls.get(resp.call_id)) |c| c.caller_addr else from;
        if (self.calls.getPtr(resp.call_id)) |call_ctx| {
            switch (resp.status_code) {
                100 => {},
                101...199 => {
                    if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                        call_ctx.state = .ringing;
                        call_ctx.callee_resp_addr = from;
                        proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse 1xx: {}", .{err});
                        };
                    }
                },
                200...299 => {
                    if (resp.cseq_method == .INVITE) {
                        if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                            call_ctx.state = .answered;
                            log.info("call {s} answered ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                            call_ctx.callee_resp_addr = from;
                            proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx: {}", .{err});
                            };
                        } else if (call_ctx.state == .canceling) {
                            call_ctx.state = .answered;
                            log.info("call {s} answered after CANCEL race ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                            call_ctx.callee_resp_addr = from;
                            proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx race: {}", .{err});
                            };
                        }
                    } else {
                        proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse non-invite: {}", .{err});
                        };
                    }
                },
                487 => {
                    if (call_ctx.state == .canceling) {
                        call_ctx.state = .terminated;
                        log.info("call {s} terminated (487)", .{resp.call_id});
                        proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse 487: {}", .{err});
                        };
                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                    }
                },
                else => {
                    if (call_ctx.state != .terminated) {
                        call_ctx.state = .terminated;
                        log.info("call {s} terminated ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                        proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse final: {}", .{err});
                        };
                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                    }
                },
            }
        } else {
            proxy.handleResponse(resp, dest_addr, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                log.err("handleResponse no-ctx: {}", .{err});
            };
        }
    }
};

test {
    std.testing.refAllDecls(@This());
}
