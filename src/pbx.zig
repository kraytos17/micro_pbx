//! Stateful PBX core: owns call table, transactions, RTP sessions, and dispatch.

const std = @import("std");

const call = @import("call.zig");
const proxy = @import("proxy.zig");
const registrar = @import("registrar.zig");
const rtp = @import("rtp.zig");
const sdp = @import("sdp.zig");
const msg = @import("sip/message.zig");
const parser = @import("sip/parser.zig");
const txn = @import("sip/transaction.zig");
const transport = @import("transport.zig");

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
            if (kv.value_ptr.*.caller_via) |v| self.allocator.free(v);
            if (kv.value_ptr.*.caller_from) |f| self.allocator.free(f);
            if (kv.value_ptr.*.caller_to) |t| self.allocator.free(t);
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
            // Drain RTP relay sockets without blocking: a zero-duration
            // timeout turns each read into a poll so SIP signaling stays
            // responsive once relay sockets exist.
            const poll = transport.pollTimeout();
            for (self.rtp_sockets.items) |*rtp_sock| {
                const rtp_result = rtp_sock.recvFromTimeout(&rtp_buf, poll) catch continue;
                rtp.handleRtpPacket(rtp_result.data, rtp_result.from, &self.rtp_sessions, &self.socket) catch continue;
            }

            // Block on SIP only until the next transaction timer fires.
            const sip_timeout = transport.timeoutMs(self.txn_layer.nextTimeout());
            const result = self.socket.recvFromTimeout(&recv_buf, sip_timeout) catch |err| {
                if (err == error.Timeout) {
                    self.handleTimeout();
                    continue;
                }

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

    /// Timer pass: resends every firing transaction request, then frees
    /// terminated transactions. Resends happen before the sweep because
    /// tick() returns slices borrowing map memory.
    fn handleTimeout(self: *Pbx) void {
        while (self.txn_layer.tick()) |ev| {
            switch (ev) {
                .retransmit => |r| {
                    self.socket.sendTo(r.data, r.addr) catch |err| {
                        log.err("retransmit {s} failed: {}", .{ r.branch, err });
                    };
                },
                .expired => |id| {
                    if (id.method == .INVITE) self.onInviteTimeout(id.branch);
                },
            }
        }
        self.txn_layer.sweepTerminated() catch |err| {
            log.err("sweepTerminated failed: {}", .{err});
        };
    }

    /// Handles a Timer B expiry: 408s the caller and tears down the call.
    /// Scans calls by invite branch (O(n), n is tiny; no index needed).
    fn onInviteTimeout(self: *Pbx, branch: []const u8) void {
        var it = self.calls.iterator();
        while (it.next()) |kv| {
            const call_ctx = kv.value_ptr;
            const invite_branch = call_ctx.invite_branch orelse continue;
            if (!std.mem.eql(u8, invite_branch, branch)) continue;

            const call_id = kv.key_ptr.*;
            var resp_buf: [2048]u8 = undefined;
            const timeout_resp = proxy.buildTimeoutResponse(
                &resp_buf,
                call_id,
                call_ctx.invite_cseq,
                call_ctx.caller_via orelse "",
                call_ctx.caller_from orelse "",
                call_ctx.caller_to orelse "",
            ) catch |err| {
                log.err("buildTimeoutResponse failed: {}", .{err});
                return;
            };

            self.socket.sendTo(timeout_resp, call_ctx.caller_addr) catch |err| {
                log.err("send 408 to caller failed: {}", .{err});
            };

            log.info("call {s} terminated (408 Request Timeout)", .{call_id});
            call.removeCall(&self.calls, self.allocator, call_id);
            return;
        }
    }

    /// Best-effort cache of a final error response under the caller's
    /// branch, mirroring the 404 path. Logs and drops on OOM.
    fn cacheErrorResponse(
        self: *Pbx,
        branch: []const u8,
        method: msg.Method,
        data: []u8,
        to: std.Io.net.IpAddress,
    ) void {
        self.txn_layer.createNonInviteTransaction(branch, method, data, to) catch |err| {
            log.err("error-cache create failed: {}", .{err});
            return;
        };
        self.txn_layer.storeResponse(branch, method, data) catch |err| {
            log.err("error-cache store failed: {}", .{err});
        };
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

        // Loop protection (RFC 3261) takes precedence over everything,
        // including retransmission replay: a 0-hop request is answered here.
        if ((req.max_forwards orelse 70) == 0) {
            log.warn("INVITE {s} rejected: Max-Forwards exhausted", .{req.request_uri});
            try proxy.sendResponse(&self.socket, from, resp_buf, 483, "Too Many Hops", req);
            return;
        }

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

        // A terminated dialog awaiting its BYE response is stale: a new
        // INVITE reusing the Call-ID starts fresh instead of stalling.
        if (call_ctx.state == .terminated) {
            call.removeCall(&self.calls, self.allocator, req.call_id);
            call_ctx = .{ .caller_addr = from };
        }

        // Stored on the success path below; 404s never create dialog state.
        if (call_ctx.state == .proceeding and call_ctx.callee_contact_addr == null) {
            const dest_aor = proxy.extractUri(req.request_uri);
            const contact = self.reg.lookup(dest_aor) orelse {
                log.warn("INVITE {s} not found, sending 404", .{dest_aor});

                // Build 404 response (top Via echoed unchanged)
                var response_buf: [2048]u8 = undefined;
                const response_404 = try proxy.buildResponse(&response_buf, 404, "Not Found", req);

                // Send the 404
                try proxy.sendResponseWithBranch(&self.socket, from, resp_buf, 404, "Not Found", req);
                // Cache the 404 response for retransmissions using client's branch
                try self.txn_layer.createNonInviteTransaction(req.via_branch, .INVITE, response_404, from);
                try self.txn_layer.storeResponse(req.via_branch, .INVITE, response_404);
                return;
            };

            call_ctx.callee_contact_addr = contact.address;
            // Create an RTP session from the caller's SDP so the media relay
            // can rewrite the callee's SDP and open relay sockets on ACK.
            if (req.content_type) |ct| {
                if (std.mem.eql(u8, ct, "application/sdp") and req.body.len > 0) {
                    if (sdp.parseSdp(req.body)) |media| {
                        _ = try self.rtp_sessions.createSession(req.call_id, media.port, from, media.payload_type);
                    } else |_| {
                        log.warn("could not parse caller SDP in INVITE", .{});
                    }
                }
            }

            const invite_result = try proxy.handleInvite(req, from, contact, &self.socket, self.pbx_addr, resp_buf, fwd_buf, arena.allocator(), self.io);

            try self.txn_layer.createInviteTransaction(invite_result.branch, invite_result.forwarded, contact.address);
            if (call_ctx.invite_branch) |old| self.allocator.free(old);

            call_ctx.invite_branch = self.allocator.dupe(u8, invite_result.branch) catch null;
            if (call_ctx.caller_via) |old| self.allocator.free(old);
            if (call_ctx.caller_from) |old| self.allocator.free(old);
            if (call_ctx.caller_to) |old| self.allocator.free(old);

            call_ctx.caller_via = self.allocator.dupe(u8, req.via) catch null;
            call_ctx.caller_from = self.allocator.dupe(u8, req.from) catch null;
            call_ctx.caller_to = self.allocator.dupe(u8, req.to) catch null;
            call_ctx.invite_cseq = req.cseq_num;
            arena.allocator().free(invite_result.branch);
            try call.putCall(&self.calls, self.allocator, req.call_id, call_ctx);
        } else {
            // Duplicate or in-dialog INVITE (call already tracked): absorb
            // silently. Re-100ing feeds retransmit storms — real stacks keep
            // Timer A running past provisionals — and risks aborting strict
            // UAs with out-of-step responses.
            log.debug("absorbed duplicate INVITE {s} branch {s}", .{ req.call_id, req.via_branch });
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
            // No dialog: nothing to acknowledge toward. Dropping avoids
            // bouncing the ACK back to its sender.
            log.debug("ACK for unknown call {s} from {}, dropping", .{ req.call_id, from });
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

            // Stop any Timer A retransmits of the original INVITE (no-op if gone).
            if (call_ctx.invite_branch) |b| self.txn_layer.removeTransaction(b, .INVITE);
            // Media stops now, but the dialog entry stays until the BYE
            // response arrives (see handleResponse) so the 200 is relayed
            // to the right side instead of bouncing back to its sender.
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
                    proxy.sendResponse(&self.socket, from, resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
                    return;
                };

                const branch = call_ctx.invite_branch orelse {
                    log.warn("CANCEL for call with no stored invite_branch", .{});
                    proxy.sendResponse(&self.socket, from, resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
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
        // Responses to PBX-originated CANCELs terminate at this hop: the
        // caller was already answered directly when its CANCEL arrived.
        if (resp.cseq_method == .CANCEL) {
            log.debug("dropping downstream CANCEL response {d}", .{resp.status_code});
            return;
        }

        const dest_addr = if (self.calls.get(resp.call_id)) |c| c.caller_addr else from;
        if (self.calls.getPtr(resp.call_id)) |call_ctx| {
            switch (msg.ResponseClass.of(resp.status_code)) {
                .provisional => {
                    if (resp.status_code == 100) {
                        // The caller already received its own 100 Trying; do not relay.
                    } else {
                        if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                            call_ctx.state = .ringing;
                            call_ctx.callee_resp_addr = from;
                            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 1xx: {}", .{err});
                            };
                        }
                    }
                },
                .success => {
                    if (resp.cseq_method == .INVITE) {
                        if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                            call_ctx.state = .answered;
                            log.info("call {s} answered ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                            call_ctx.callee_resp_addr = from;
                            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx: {}", .{err});
                            };
                            // RFC 3261: INVITE client transaction ends on 2xx, no Timer D.
                            self.txn_layer.removeTransaction(resp.via_branch, .INVITE);
                        } else if (call_ctx.state == .canceling) {
                            call_ctx.state = .answered;
                            log.info("call {s} answered after CANCEL race ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                            call_ctx.callee_resp_addr = from;
                            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx race: {}", .{err});
                            };
                            self.txn_layer.removeTransaction(resp.via_branch, .INVITE);
                        }
                    } else {
                        proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse non-invite: {}", .{err});
                        };

                        self.txn_layer.storeResponse(resp.via_branch, resp.cseq_method, data) catch |err| {
                            log.err("storeResponse failed: {}", .{err});
                        };

                        self.txn_layer.setCompleted(resp.via_branch, resp.cseq_method);
                        // A terminating dialog ends when its BYE is answered.
                        if (call_ctx.state == .terminated) {
                            log.info("call {s} removed on BYE response", .{resp.call_id});
                            call.removeCall(&self.calls, self.allocator, resp.call_id);
                            self.rtp_sessions.removeSession(resp.call_id);
                        }
                    }
                },
                .redirect, .client_error, .server_error, .global_error => {
                    if (resp.status_code == 487 and call_ctx.state == .canceling) {
                        call_ctx.state = .terminated;
                        log.info("call {s} terminated (487)", .{resp.call_id});
                        proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse 487: {}", .{err});
                        };

                        self.txn_layer.storeResponse(resp.via_branch, resp.cseq_method, data) catch |err| {
                            log.err("storeResponse failed: {}", .{err});
                        };

                        self.txn_layer.setCompleted(resp.via_branch, resp.cseq_method);
                        // Cache under the caller's branch too, so a caller
                        // INVITE retransmit replays instead of re-forwarding.
                        if (resp.via_branch2.len > 0) {
                            self.cacheErrorResponse(resp.via_branch2, resp.cseq_method, data, dest_addr);
                        }
                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                    } else if (call_ctx.state != .terminated) {
                        call_ctx.state = .terminated;
                        log.info("call {s} terminated ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                        proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse final: {}", .{err});
                        };

                        self.txn_layer.storeResponse(resp.via_branch, resp.cseq_method, data) catch |err| {
                            log.err("storeResponse failed: {}", .{err});
                        };

                        self.txn_layer.setCompleted(resp.via_branch, resp.cseq_method);
                        // Cache under the caller's branch too, so a caller
                        // INVITE retransmit replays instead of re-forwarding.
                        if (resp.via_branch2.len > 0) {
                            self.cacheErrorResponse(resp.via_branch2, resp.cseq_method, data, dest_addr);
                        }
                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                    }
                },
            }
        } else {
            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                log.err("handleResponse no-ctx: {}", .{err});
            };
        }
    }
};

test {
    std.testing.refAllDecls(@This());
}

const test_alice_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5070 } };
const test_bob_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5072 } };

fn parseRequest(raw: []const u8) !msg.Request {
    return (try parser.parse(raw)).request;
}

fn parseResponse(raw: []const u8) !msg.Response {
    return (try parser.parse(raw)).response;
}

fn registerUser(pbx: *Pbx, name: []const u8, from: std.Io.net.IpAddress, resp_buf: []u8) !void {
    var raw_buf: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "REGISTER sip:{s}@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKreg{s}\r\n" ++
        "From: <sip:{s}@127.0.0.1:5060>;tag=tag{s}\r\n" ++
        "To: <sip:{s}@127.0.0.1:5060>\r\n" ++
        "Call-ID: {s}reg@127.0.0.1\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:{s}@127.0.0.1>\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{ name, name, name, name, name, name, name }) catch unreachable;
    const req = try parseRequest(raw);
    try pbx.onRegister(req, from, resp_buf);
}

fn inviteBob(pbx: *Pbx, call_id: []const u8, branch: []const u8, from: std.Io.net.IpAddress, with_sdp: bool, resp_buf: []u8, fwd_buf: []u8) !void {
    const sdp_body =
        "v=0\r\n" ++
        "o=alice 123456 789 IN IP4 127.0.0.1\r\n" ++
        "s=Session\r\n" ++
        "c=IN IP4 127.0.0.1\r\n" ++
        "m=audio 20000 RTP/AVP 0\r\n";
    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch={s}\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: {s}\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Content-Type: application/sdp\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n" ++
        "{s}", .{ branch, call_id, sdp_body.len, if (with_sdp) sdp_body else "" }) catch unreachable;
    const req = try parseRequest(raw);
    try pbx.onInvite(req, from, resp_buf, fwd_buf);
}

fn deliverResponse(pbx: *Pbx, raw: []const u8, from: std.Io.net.IpAddress, fwd_buf: []u8) !void {
    var data_buf: [1024]u8 = undefined;
    @memcpy(data_buf[0..raw.len], raw);
    const data = data_buf[0..raw.len];
    const resp = try parseResponse(data);
    pbx.handleResponse(resp, data, from, fwd_buf);
}

test "e2e full call flow REGISTER INVITE 180 200 ACK BYE" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;

    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:alice") != null);
    try std.testing.expect(server.reg.lookup("sip:alice@127.0.0.1:5060") != null);

    try registerUser(&server, "bob", test_bob_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:bob") != null);

    const call_id = "call-1";
    try inviteBob(&server, call_id, "z9hG4bKinv1", test_alice_addr, false, &resp_buf, &fwd_buf);
    const call_ctx = server.calls.get(call_id).?;
    try std.testing.expect(call_ctx.state == .proceeding);
    try std.testing.expectEqual(test_bob_addr, call_ctx.callee_contact_addr.?);

    // 180 Ringing from callee
    try deliverResponse(&server, "SIP/2.0 180 Ringing\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKinv1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .ringing);

    // 200 OK from callee
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKinv1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .answered);

    // ACK from caller
    const ack_req = try parseRequest("ACK sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKack1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 1 ACK\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onAck(ack_req, test_alice_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .established);

    // BYE from caller
    const bye_req = try parseRequest("BYE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbye1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onBye(bye_req, test_alice_addr, &fwd_buf);
    // Dialog lingers as terminated until the BYE is answered...
    try std.testing.expect(server.calls.get(call_id).?.state == .terminated);

    // ...and the 200 to BYE relays to the caller and removes the dialog.
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbye1resp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id) == null);
}

test "e2e INVITE unknown user 404 and retransmission cache" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:nobody@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK404\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:nobody@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-404@127.0.0.1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{}) catch unreachable;
    const req = try parseRequest(raw);
    try server.onInvite(req, test_alice_addr, &resp_buf, &fwd_buf);
    // 404s create no dialog state...
    try std.testing.expect(server.calls.get("call-404@127.0.0.1") == null);
    // ...but the 404 is cached under the client branch...
    const cached_txn = server.txn_layer.getTransaction("z9hG4bK404", .INVITE).?;
    try std.testing.expect(cached_txn.response_buf != null);

    // ...so a retransmission replays the cached 404 with no call mutation.
    try server.onInvite(req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get("call-404@127.0.0.1") == null);
}

test "e2e CANCEL then 2xx race goes to answered" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-race";
    try inviteBob(&server, call_id, "z9hG4bKrace", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .proceeding);

    const cancel_req = try parseRequest("CANCEL sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcancel\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-race\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onCancel(cancel_req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .canceling);

    // Callee's 2xx arrives anyway (race)
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKrace\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-race\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .answered);
}

test "e2e CANCEL then 487 terminates and removes call" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-487";
    try inviteBob(&server, call_id, "z9hG4bK487", test_alice_addr, false, &resp_buf, &fwd_buf);

    const cancel_req = try parseRequest("CANCEL sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcancel2\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-487\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onCancel(cancel_req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .canceling);

    try deliverResponse(&server, "SIP/2.0 487 Request Terminated\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK487\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-487\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id) == null);
}

test "e2e registration expiry with short TTL" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var raw_buf: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "REGISTER sip:short@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKshort\r\n" ++
        "From: <sip:short@127.0.0.1:5060>;tag=tagshort\r\n" ++
        "To: <sip:short@127.0.0.1:5060>\r\n" ++
        "Call-ID: shortreg@127.0.0.1\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:short@127.0.0.1>\r\n" ++
        "Expires: 1\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{}) catch unreachable;
    const req = try parseRequest(raw);

    var resp_buf: [4096]u8 = undefined;
    try server.onRegister(req, test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:short") != null);

    std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(2000), .real) catch unreachable;
    try std.testing.expect(server.reg.lookup("sip:short") == null);
}

test "e2e RTP session created on INVITE with SDP, sockets opened on ACK" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-rtp";
    try inviteBob(&server, call_id, "z9hG4bKrtp", test_alice_addr, true, &resp_buf, &fwd_buf);

    const session = server.rtp_sessions.getSession(call_id).?;
    try std.testing.expectEqual(@as(u16, 20000), session.caller_rtp_port);
    try std.testing.expectEqual(@as(u7, 0), session.caller_payload_type);

    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKrtp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-rtp\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:bob@127.0.0.1>\r\n" ++
        "Content-Type: application/sdp\r\n" ++
        "Content-Length: 82\r\n" ++
        "\r\n" ++
        "v=0\r\n" ++
        "o=bob 123456 789 IN IP4 127.0.0.1\r\n" ++
        "s=Session\r\n" ++
        "c=IN IP4 127.0.0.1\r\n" ++
        "m=audio 4000 RTP/AVP 0\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expectEqual(test_bob_addr, session.callee_ip);
    try std.testing.expectEqual(@as(u7, 0), session.callee_payload_type);

    // ACK opens the two relay sockets
    const ack_req = try parseRequest("ACK sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKackrtp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-rtp\r\n" ++
        "CSeq: 1 ACK\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onAck(ack_req, test_alice_addr, &fwd_buf);
    try std.testing.expectEqual(@as(usize, 2), server.rtp_sockets.items.len);

    // BYE removes the session
    const bye_req = try parseRequest("BYE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbyertp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-rtp\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onBye(bye_req, test_alice_addr, &fwd_buf);
    try std.testing.expect(server.rtp_sessions.getSession(call_id) == null);
}

test "e2e duplicate REGISTER retransmission replays 200 OK" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var raw_buf: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "REGISTER sip:dup@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKdup\r\n" ++
        "From: <sip:dup@127.0.0.1:5060>;tag=tagdup\r\n" ++
        "To: <sip:dup@127.0.0.1:5060>\r\n" ++
        "Call-ID: dupreg@127.0.0.1\r\n" ++
        "CSeq: 5 REGISTER\r\n" ++
        "Contact: <sip:dup@127.0.0.1>\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{}) catch unreachable;
    const req = try parseRequest(raw);
    try server.onRegister(req, test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:dup") != null);

    // Retransmission with a lower CSeq (same Call-ID) must not error
    var raw2_buf: [512]u8 = undefined;
    const raw2 = std.fmt.bufPrint(&raw2_buf, "REGISTER sip:dup@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKdup2\r\n" ++
        "From: <sip:dup@127.0.0.1:5060>;tag=tagdup\r\n" ++
        "To: <sip:dup@127.0.0.1:5060>\r\n" ++
        "Call-ID: dupreg@127.0.0.1\r\n" ++
        "CSeq: 3 REGISTER\r\n" ++
        "Contact: <sip:dup@127.0.0.1>\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{}) catch unreachable;
    const req2 = try parseRequest(raw2);
    try server.onRegister(req2, test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:dup") != null);
}

test "e2e CANCEL with missing callee sends 481" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);

    // Insert a call manually in proceeding state with no callee contact
    const call_id = "call-nocallee";
    try call.putCall(&server.calls, server.allocator, call_id, .{ .caller_addr = test_alice_addr });

    const cancel_req = try parseRequest("CANCEL sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcnocallee\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-nocallee\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    // Must not error: the 481 is sent internally
    try server.onCancel(cancel_req, test_alice_addr, &resp_buf, &fwd_buf);
}

test "e2e handleTimeout retransmits overdue INVITE transaction" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-timer";
    try inviteBob(&server, call_id, "z9hG4bKtimer", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expectEqual(@as(usize, 1), server.txn_layer.map.count());

    // Force the forwarded INVITE transaction (PBX-generated branch) overdue.
    var it = server.txn_layer.map.iterator();
    const stored = it.next().?;
    const branch = stored.key_ptr.branch;
    const method = stored.key_ptr.method;
    stored.value_ptr.next_fire_at_ms = 0;

    // handleTimeout resends over loopback UDP and backs the timer off.
    server.handleTimeout();
    const fired_txn = server.txn_layer.getTransaction(branch, method).?;
    try std.testing.expectEqual(@as(u8, 1), fired_txn.retransmit_count);
    try std.testing.expectEqual(@as(u32, 1000), fired_txn.t1_ms);
}

test "e2e Timer B expiry sends 408 and tears down the call" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-timeout";
    try inviteBob(&server, call_id, "z9hG4bKtimeout", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.state == .proceeding);

    // Arm Timer B on the forwarded-INVITE transaction and force it overdue.
    var it = server.txn_layer.map.iterator();
    const stored = it.next().?;
    stored.value_ptr.timer_b_fired = true;
    stored.value_ptr.next_fire_at_ms = 0;

    server.handleTimeout();

    // Caller got the 408 (verified byte-exact at the builder level);
    // the call is gone and the transaction is swept.
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(@as(usize, 0), server.txn_layer.map.count());
}

test "e2e 2xx removes the INVITE client transaction" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-2xx";
    try inviteBob(&server, call_id, "z9hG4bK2xx", test_alice_addr, false, &resp_buf, &fwd_buf);
    const invite_branch = server.calls.get(call_id).?.invite_branch.?;

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch={s}\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-2xx\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{invite_branch}) catch unreachable;
    try deliverResponse(&server, raw, test_bob_addr, &fwd_buf);

    try std.testing.expect(server.calls.get(call_id).?.state == .answered);
    try std.testing.expect(server.txn_layer.getTransaction(invite_branch, .INVITE) == null);
}

test "e2e 486 completes the transaction and Timer D sweeps it" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-busy";
    try inviteBob(&server, call_id, "z9hG4bKbusy", test_alice_addr, false, &resp_buf, &fwd_buf);
    // Own the branch: handleResponse tears down the call (freeing the
    // map-owned slice) before we look the transaction up below.
    const invite_branch = try std.testing.allocator.dupe(u8, server.calls.get(call_id).?.invite_branch.?);
    defer std.testing.allocator.free(invite_branch);

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "SIP/2.0 486 Busy Here\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch={s}\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-busy\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{invite_branch}) catch unreachable;
    try deliverResponse(&server, raw, test_bob_addr, &fwd_buf);

    // Final error: call torn down, response cached, transaction completed.
    try std.testing.expect(server.calls.get(call_id) == null);
    const tm = server.txn_layer.getTransaction(invite_branch, .INVITE);
    try std.testing.expect(tm != null);
    try std.testing.expectEqual(txn.TransactionState.completed, tm.?.state);
    try std.testing.expect(tm.?.response_buf != null);

    // Timer D expiry terminates silently; the sweep frees the entry.
    tm.?.next_fire_at_ms = 0;
    server.handleTimeout();
    try std.testing.expect(server.txn_layer.getTransaction(invite_branch, .INVITE) == null);
}

test "e2e BYE removes the INVITE client transaction" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-byetxn";
    try inviteBob(&server, call_id, "z9hG4bKbyetxn", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expectEqual(@as(usize, 1), server.txn_layer.map.count());

    const bye_req = try parseRequest("BYE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbyetxn1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-byetxn\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onBye(bye_req, test_alice_addr, &fwd_buf);
    // INVITE transaction gone, dialog kept as terminated...
    try std.testing.expectEqual(@as(usize, 0), server.txn_layer.map.count());
    try std.testing.expect(server.calls.get(call_id).?.state == .terminated);

    // ...until the 200 to BYE arrives and removes it.
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbyetxnresp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-byetxn\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id) == null);
}

test "e2e 486 retransmit replays cached error instead of re-forwarding" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-486re";
    try inviteBob(&server, call_id, "z9hG4bKre", test_alice_addr, false, &resp_buf, &fwd_buf);
    const invite_branch = server.calls.get(call_id).?.invite_branch.?;
    try std.testing.expectEqual(@as(usize, 1), server.txn_layer.map.count());

    // 486 with both Vias: PBX branch first, caller branch second.
    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "SIP/2.0 486 Busy Here\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch={s}\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKre\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-486re\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{invite_branch}) catch unreachable;
    try deliverResponse(&server, raw, test_bob_addr, &fwd_buf);

    // Call torn down; completed invite txn + client-branch error cache remain.
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(@as(usize, 2), server.txn_layer.map.count());
    try std.testing.expect(server.txn_layer.getTransaction("z9hG4bKre", .INVITE).?.response_buf != null);

    // Caller retransmits the INVITE: replay, no re-forward, no new state.
    try inviteBob(&server, call_id, "z9hG4bKre", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(@as(usize, 2), server.txn_layer.map.count());
}

test "e2e INVITE with exhausted Max-Forwards gets no dialog" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKmf0\r\n" ++
        "Max-Forwards: 0\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-mf0@127.0.0.1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{}) catch unreachable;
    const req = try parseRequest(raw);
    try server.onInvite(req, test_alice_addr, &resp_buf, &fwd_buf);

    // 483 answered (send goes to loopback, unobserved); nothing stored.
    try std.testing.expect(server.calls.get("call-mf0@127.0.0.1") == null);
    try std.testing.expectEqual(@as(usize, 0), server.txn_layer.map.count());
}
