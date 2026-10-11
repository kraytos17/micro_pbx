//! Stateful PBX core: owns call table, transactions, RTP sessions, and dispatch.

const std = @import("std");

const auth = @import("auth.zig");
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

/// Registrar sweep cadence: stale contacts linger at most this long past
/// expiry when nobody looks them up. Tunable.
pub const reg_sweep_interval_ms: i64 = 60_000;
/// RTP poll quantum: while any relay session holds open sockets, the run
/// loop wakes this often instead of sleeping to the next SIP timeout.
/// 20ms matches voice packetization; idle PBXs (no open relays) still
/// sleep full SIP deadlines.
pub const rtp_poll_interval_ms: i64 = 20;

/// A running PBX server: owns all mutable state and the dispatch loop.
pub const Pbx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: transport.UdpSocket,
    reg: registrar.Registrar,
    auth: auth.Auth,
    txn_layer: txn.TransactionLayer,
    calls: std.StringHashMap(call.Dialog),
    rtp_sessions: rtp.Sessions,
    pbx_addr: std.Io.net.IpAddress,
    /// Scratch arena, reset every event-loop iteration. Anything stored
    /// past the iteration must be duped onto allocator first.
    scratch: std.heap.ArenaAllocator,
    /// Last registrar sweep (ms). Checked once per loop; the scan itself
    /// only runs when due, so idle loops stay a single clock read.
    last_reg_sweep_ms: i64,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16) !Pbx {
        var self = Pbx{
            .allocator = allocator,
            .io = io,
            .socket = try transport.UdpSocket.init(io, port),
            .reg = registrar.Registrar.init(allocator, io),
            .auth = auth.Auth.init(allocator, io),
            .txn_layer = txn.TransactionLayer.init(allocator, io),
            .calls = std.StringHashMap(call.Dialog).init(allocator),
            .rtp_sessions = rtp.Sessions.init(allocator),
            .pbx_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = port } },
            .scratch = std.heap.ArenaAllocator.init(allocator),
            .last_reg_sweep_ms = 0,
        };

        errdefer self.deinit();
        // Fallback credential store (main loads users.conf over these when
        // present). Passwords must match interop/register.py's credentials.
        try self.auth.addUser("alice", "alicepass");
        try self.auth.addUser("bob", "bobpass");
        try self.auth.addUser("silent", "silentpass");
        return self;
    }

    pub fn deinit(self: *Pbx) void {
        self.socket.deinit();
        self.reg.deinit();
        self.auth.deinit();
        self.txn_layer.deinit();

        var it = self.calls.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.arena.deinit();
            self.allocator.destroy(kv.value_ptr.arena);
            self.allocator.free(kv.key_ptr.*);
        }

        self.calls.deinit();
        self.rtp_sessions.deinit();
        self.scratch.deinit();
    }

    /// Main event loop: drains RTP sockets, then blocks on the SIP socket.
    pub fn run(self: *Pbx) !void {
        var recv_buf: [4096]u8 = undefined;
        var resp_buf: [4096]u8 = undefined;
        var fwd_buf: [4096]u8 = undefined;
        var rtp_buf: [2048]u8 = undefined;
        while (true) {
            // Scratch reset: bounds per-iteration temporaries (INVITE branch,
            // rewritten SDP) without per-request allocator churn.
            _ = self.scratch.reset(.retain_capacity);

            // Drain relay sockets (session-owned, non-blocking poll).
            self.rtp_sessions.drain(&self.socket, &rtp_buf);
            // Reap expired registrations when due (lazy expiry alone would
            // leak contacts nobody looks up again).
            const now_ms = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toMilliseconds();
            if (now_ms - self.last_reg_sweep_ms >= reg_sweep_interval_ms) {
                self.last_reg_sweep_ms = now_ms;
                const reaped = self.reg.sweepExpired();
                if (reaped > 0) log.debug("swept {} expired registrations", .{reaped});
            }

            // Block on SIP until the next transaction timer fires, across
            // both the server cache and dialog client transactions — but
            // never longer than the RTP quantum while media may be flowing,
            // or relayed packets sit unread between SIP events.
            var sleep_ms: i64 = @min(
                self.txn_layer.nextTimeout(),
                call.nextDialogTimeout(&self.calls, now_ms),
            );
            if (self.rtp_sessions.hasOpenRelays()) {
                sleep_ms = @min(sleep_ms, rtp_poll_interval_ms);
            }
            const result = self.socket.recvFromTimeout(&recv_buf, transport.timeoutMs(sleep_ms)) catch |err| {
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
        try proxy.handleRegister(req, from, &self.reg, &self.auth, &self.socket, resp_buf, self.allocator);
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

        // Dialog client transactions share the tickOne step. Expired ids are
        // collected first: onInviteTimeout removes dialogs mid-iteration.
        const now_ms = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toMilliseconds();
        var expired: std.ArrayList(txn.TransactionId) = .empty;
        defer expired.deinit(self.allocator);

        var dit = self.calls.iterator();
        while (dit.next()) |entry| {
            const dlg = entry.value_ptr;
            if (dlg.invite_txn) |*t| {
                if (txn.tickOne(now_ms, t.id, t)) |ev| {
                    switch (ev) {
                        .retransmit => |r| {
                            self.socket.sendTo(r.data, r.addr) catch |err| {
                                log.err("retransmit {s} failed: {}", .{ r.branch, err });
                            };
                        },
                        .expired => |id| {
                            if (id.method == .INVITE) {
                                expired.append(self.allocator, id) catch |err| {
                                    log.err("expiry queue failed: {}", .{err});
                                };
                            }
                        },
                    }
                }
            }
        }
        for (expired.items) |id| {
            self.onInviteTimeout(id.branch);
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
            const dlg = kv.value_ptr;
            const call_ctx = &dlg.call;
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
        // Scratch space is reset every event-loop iteration; anything kept
        // past this call is duped onto the heap first (see call sites).
        const arena = self.scratch.allocator();
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

        var dlg_ptr: ?*call.Dialog = null;
        if (self.calls.getPtr(req.call_id)) |dlg| {
            if (dlg.call.state == .terminated) {
                call.removeCall(&self.calls, self.allocator, req.call_id);
            } else {
                dlg_ptr = dlg;
            }
        }
        // Peek only: 404s must not create dialog state (creation happens on
        // the success path via ensureDialog below).
        const call_ctx: call.Call = if (dlg_ptr) |d| d.call else .{ .caller_addr = from };
        // Stored on the success path below; 404s never create dialog state.
        if (call_ctx.state == .proceeding and call_ctx.callee_contact_addr == null) {
            // INVITE authentication, challenge-first like REGISTER: unknown
            // users 401 here and never reach the lookup below (no user
            // enumeration). Duplicates and in-dialog INVITEs take the absorb
            // branch instead and skip this — a Timer-A retransmit carries a
            // consumed nonce and must not re-challenge.
            const username = self.auth.verifyRequest(req) catch |err| {
                const stale = err == error.StaleNonce;
                if (stale) log.info("stale nonce for {s}, re-challenging", .{req.request_uri});
                try proxy.sendUnauthorized(&self.socket, from, &self.auth, resp_buf, req, self.allocator, stale);
                return;
            };

            log.debug("INVITE {s} authenticated as {s}", .{ req.request_uri, username });
            const dest_aor = proxy.extractUri(req.request_uri);
            const contact = self.reg.lookup(dest_aor) orelse {
                log.warn("INVITE {s} not found, sending 404", .{dest_aor});

                // Build 404 response (top Via echoed unchanged)
                var response_buf: [2048]u8 = undefined;
                const response_404 = try proxy.buildResponse(&response_buf, 404, "Not Found", req, null);

                // Send the 404
                try proxy.sendResponseWithBranch(&self.socket, from, resp_buf, 404, "Not Found", req);
                // Cache the 404 response for retransmissions using client's branch.
                // Under table pressure the 404 already went out; only the
                // cache entry is skipped (storeResponse no-ops on a miss).
                self.txn_layer.createNonInviteTransaction(req.via_branch, .INVITE, response_404, from) catch |err| {
                    log.warn("dropped 404 cache entry under load: {}", .{err});
                };

                try self.txn_layer.storeResponse(req.via_branch, .INVITE, response_404);
                return;
            };

            // Dialog contact is stored below, after ensureDialog.
            // Overload gate (404s never reach here): no slot left and no
            // existing dialog means a 503, before any work is done.
            if (dlg_ptr == null and self.calls.count() >= call.max_dialogs) {
                try proxy.sendResponse(&self.socket, from, resp_buf, 503, "Service Unavailable", req);
                return;
            }
            // Create an RTP session from the caller's SDP so the media relay
            // can rewrite the callee's SDP and open relay sockets on ACK.
            // The forwarded INVITE carries SDP rewritten toward the PBX so
            // the callee's media flows through the relay (not direct).
            var invite_req = req;
            if (req.content_type) |ct| {
                if (std.mem.eql(u8, ct, "application/sdp") and req.body.len > 0) {
                    if (sdp.parseSdp(req.body)) |media| {
                        const session = try self.rtp_sessions.createSession(req.call_id, media.port, from, media.payload_type);
                        invite_req.body = try sdp.rewriteSdp(req.body, "127.0.0.1", session.relay_callee_port, arena);
                    } else |_| {
                        log.warn("could not parse caller SDP in INVITE", .{});
                    }
                }
            }

            const invite_result = try proxy.handleInvite(invite_req, from, contact, &self.socket, self.pbx_addr, resp_buf, fwd_buf, arena, self.io);

            // Ensure the dialog (dlg_ptr may have dangled across a rehash;
            // use dlg2 below, never dlg_ptr past this point).
            const dlg2 = try call.ensureDialog(&self.calls, self.allocator, req.call_id, .{ .caller_addr = from });
            const ctx = &dlg2.call;
            ctx.callee_contact_addr = contact.address;

            // Client transaction lives in the dialog (arena-owned buffers).
            // Under pressure the forward still stands; only tracking drops.
            const now_ms = std.Io.Timestamp.now(self.io, std.Io.Clock.real).toMilliseconds();
            if (txn.makeTransaction(dlg2.arena.allocator(), now_ms, invite_result.branch, .INVITE, .invite, invite_result.forwarded, contact.address)) |t| {
                dlg2.invite_txn = t;
            } else |err| {
                log.warn("untracked INVITE leg under pressure: {}", .{err});
            }

            const dialog_alloc = dlg2.arena.allocator();
            ctx.invite_branch = dialog_alloc.dupe(u8, invite_result.branch) catch null;
            ctx.caller_via = dialog_alloc.dupe(u8, req.via) catch null;
            ctx.caller_from = dialog_alloc.dupe(u8, req.from) catch null;
            ctx.caller_to = dialog_alloc.dupe(u8, req.to) catch null;
            ctx.invite_cseq = req.cseq_num;
            // invite_result.branch lives in scratch (reset per iteration).
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
        if (self.calls.getPtr(req.call_id)) |dlg| {
            const call_ctx = &dlg.call;
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
                if (transport.UdpSocket.init(self.io, session.relay_caller_port)) |sock| {
                    session.caller_sock = sock;
                } else |err| {
                    log.err("caller relay socket failed: {}", .{err});
                }

                if (transport.UdpSocket.init(self.io, session.relay_callee_port)) |sock| {
                    session.callee_sock = sock;
                } else |err| {
                    log.err("callee relay socket failed: {}", .{err});
                }
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

        if (self.calls.getPtr(req.call_id)) |dlg| {
            const call_ctx = &dlg.call;
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
            dlg.invite_txn = null;
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
        if (self.calls.getPtr(req.call_id)) |dlg| {
            const call_ctx = &dlg.call;
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

    /// In-dialog response destination: the request path in reverse.
    /// INVITE answers always go caller-ward (dest_addr), but a response to
    /// a callee-originated request (BYE from bob) must go back to the
    /// callee. Same leg-flip as onBye; shared by the 2xx and post-teardown
    /// non-INVITE arms so the two can't diverge again.
    fn responseDest(call_ctx: *const call.Call, from: std.Io.net.IpAddress) std.Io.net.IpAddress {
        if (call.addressEqual(from, call_ctx.caller_addr)) {
            return call_ctx.callee_contact_addr orelse from;
        }
        return call_ctx.caller_addr;
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

        const dest_addr = if (self.calls.get(resp.call_id)) |c| c.call.caller_addr else from;
        if (self.calls.getPtr(resp.call_id)) |dlg| {
            const call_ctx = &dlg.call;
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
                            // Pre-answer 408 context is dead weight from here;
                            // the arena reclaims it at teardown.
                            call_ctx.caller_via = null;
                            call_ctx.caller_from = null;
                            call_ctx.caller_to = null;
                            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx: {}", .{err});
                            };
                            // RFC 3261: INVITE client transaction ends on 2xx, no Timer D.
                            dlg.invite_txn = null;
                        } else if (call_ctx.state == .canceling) {
                            call_ctx.state = .answered;
                            log.info("call {s} answered after CANCEL race ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                            call_ctx.callee_resp_addr = from;
                            call_ctx.caller_via = null;
                            call_ctx.caller_from = null;
                            call_ctx.caller_to = null;
                            proxy.handleResponse(resp, dest_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                                log.err("handleResponse 2xx race: {}", .{err});
                            };
                            dlg.invite_txn = null;
                        }
                    } else {
                        // In-dialog non-INVITE responses travel the request
                        // path in reverse (responseDest): a callee-originated
                        // BYE is answered toward the callee, not the caller.
                        // The shared dest_addr default is caller-ward (correct
                        // for INVITE answers only); using it here bounces
                        // the 200 back to its sender and the callee times
                        // out waiting (live callee-BYE interop failed on
                        // exactly this).
                        const peer_addr = responseDest(call_ctx, from);
                        proxy.handleResponse(resp, peer_addr, from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse non-invite: {}", .{err});
                        };

                        // No non-INVITE client transactions exist anywhere
                        // (createNonInviteTransaction serves only server-side
                        // caches), so there is nothing to track here.
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
                        dlg.storeInviteResponse(data) catch |err| {
                            log.err("storeInviteResponse failed: {}", .{err});
                        };

                        dlg.completeInviteTxn(std.Io.Timestamp.now(self.io, std.Io.Clock.real).toMilliseconds());
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
                        dlg.storeInviteResponse(data) catch |err| {
                            log.err("storeInviteResponse failed: {}", .{err});
                        };

                        dlg.completeInviteTxn(std.Io.Timestamp.now(self.io, std.Io.Clock.real).toMilliseconds());
                        // Cache under the caller's branch too, so a caller
                        // INVITE retransmit replays instead of re-forwarding.
                        if (resp.via_branch2.len > 0) {
                            self.cacheErrorResponse(resp.via_branch2, resp.cseq_method, data, dest_addr);
                        }
                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                    } else if (resp.cseq_method != .INVITE) {
                        // Post-teardown non-INVITE final (e.g. a rejected
                        // callee-BYE: onBye already terminated the dialog at
                        // forward time). Route to the request sender like 2xx
                        // and remove the dialog — but cache nothing: an
                        // INVITE-response cache must never hold a BYE final.
                        // Without this arm the response drops and the dialog
                        // leaks (live callee-BYE-rejected interop).
                        log.info("call {s} torn down on BYE final ({d} {s})", .{ resp.call_id, resp.status_code, resp.reason_phrase });
                        proxy.handleResponse(resp, responseDest(call_ctx, from), from, &self.socket, data, &self.rtp_sessions, self.allocator, fwd_buf) catch |err| {
                            log.err("handleResponse post-teardown: {}", .{err});
                        };

                        call.removeCall(&self.calls, self.allocator, resp.call_id);
                        self.rtp_sessions.removeSession(resp.call_id);
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

// Unit-test peer addresses. Ports MUST avoid the interop suite's loopback
// map (conftest.py): PBX 5060, UAC 5061, silent 5063, UAS 5070. Unit tests
// emit real UDP via sendTo, and sipp aborts on any unexpected datagram —
// sharing a port flakes the interop suite when both run on one host.
const test_alice_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5090 } };

const test_bob_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5092 } };

fn parseRequest(raw: []const u8) !msg.Request {
    return (try parser.parse(raw)).request;
}

fn parseResponse(raw: []const u8) !msg.Response {
    return (try parser.parse(raw)).response;
}

/// Bare REGISTER (expect 401) followed by an authenticated retry.
/// Non-seeded users must be added via server.auth.addUser first; the
/// password travels explicitly because the server stores only HA1.
fn registerHandshake(
    server: *Pbx,
    name: []const u8,
    password: []const u8,
    from: std.Io.net.IpAddress,
    resp_buf: []u8,
    call_id: []const u8,
    cseq: u32,
    expires: u32,
) !void {
    var raw_buf: [2048]u8 = undefined;
    const template = "REGISTER sip:{s}@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKreg{s}\r\n" ++
        "From: <sip:{s}@127.0.0.1:5060>;tag=tag{s}\r\n" ++
        "To: <sip:{s}@127.0.0.1:5060>\r\n" ++
        "Call-ID: {s}\r\n" ++
        "CSeq: {d} REGISTER\r\n" ++
        "Contact: <sip:{s}@127.0.0.1>\r\n" ++
        "{s}" ++
        "Expires: {d}\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    const bare = std.fmt.bufPrint(&raw_buf, template, .{ name, name, name, name, name, call_id, cseq, name, "", expires }) catch unreachable;
    try server.onRegister(try parseRequest(bare), from, resp_buf);

    const nonce = try server.auth.issueNonce();
    var uri_buf: [64]u8 = undefined;
    const uri = std.fmt.bufPrint(&uri_buf, "sip:{s}@127.0.0.1:5060", .{name}) catch unreachable;
    const header = try auth.clientResponse(server.allocator, name, password, nonce[0..], "REGISTER", uri);
    defer server.allocator.free(header);
    var auth_line_buf: [512]u8 = undefined;
    const auth_line = std.fmt.bufPrint(&auth_line_buf, "Authorization: {s}\r\n", .{header}) catch unreachable;
    const raw = std.fmt.bufPrint(&raw_buf, template, .{ name, name, name, name, name, call_id, cseq, name, auth_line, expires }) catch unreachable;
    try server.onRegister(try parseRequest(raw), from, resp_buf);
}

/// Test-only passwords for the seeded users (the server stores HA1).
fn testPassword(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "alice")) return "alicepass";
    if (std.mem.eql(u8, name, "bob")) return "bobpass";
    unreachable;
}

fn registerUser(pbx: *Pbx, name: []const u8, from: std.Io.net.IpAddress, resp_buf: []u8) !void {
    var call_id_buf: [64]u8 = undefined;
    const call_id = std.fmt.bufPrint(&call_id_buf, "{s}reg@127.0.0.1", .{name}) catch unreachable;
    try registerHandshake(pbx, name, testPassword(name), from, resp_buf, call_id, 1, 3600);
}

fn inviteHandshake(pbx: *Pbx, call_id: []const u8, branch: []const u8, from: std.Io.net.IpAddress, with_sdp: bool, resp_buf: []u8, fwd_buf: []u8) !void {
    // Unit-test shortcut mirroring registerHandshake: issue a nonce straight
    // from the server instead of a bare-INVITE round trip (dedicated tests
    // cover the bare→401 leg). The authed leg is byte-real: built, parsed,
    // and dispatched like wire traffic.
    const sdp_body =
        "v=0\r\n" ++
        "o=alice 123456 789 IN IP4 127.0.0.1\r\n" ++
        "s=Session\r\n" ++
        "c=IN IP4 127.0.0.1\r\n" ++
        "m=audio 20000 RTP/AVP 0\r\n";
    const nonce = try pbx.auth.issueNonce();
    const header = try auth.clientResponse(pbx.allocator, "alice", "alicepass", nonce[0..], "INVITE", "sip:bob@127.0.0.1:5060");
    defer pbx.allocator.free(header);
    var auth_line_buf: [512]u8 = undefined;
    const auth_line = std.fmt.bufPrint(&auth_line_buf, "Authorization: {s}\r\n", .{header}) catch unreachable;
    var raw_buf: [2048]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch={s}\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: {s}\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "{s}" ++
        "Content-Type: application/sdp\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n" ++
        "{s}", .{ branch, call_id, auth_line, sdp_body.len, if (with_sdp) sdp_body else "" }) catch unreachable;
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
    try inviteHandshake(&server, call_id, "z9hG4bKinv1", test_alice_addr, false, &resp_buf, &fwd_buf);
    const call_ctx = server.calls.get(call_id).?.call;
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
    try std.testing.expect(server.calls.get(call_id).?.call.state == .ringing);

    // 200 OK from callee
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKinv1\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .answered);

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
    try std.testing.expect(server.calls.get(call_id).?.call.state == .established);

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
    try std.testing.expect(server.calls.get(call_id).?.call.state == .terminated);

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

test "e2e authed INVITE unknown user 404 and retransmission cache" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);

    // Alice authenticates (valid credential) but dials an unregistered AOR:
    // auth passes, lookup misses, 404 answers. Bare INVITEs never reach
    // here (401 first) — unknown users can't authenticate at all.
    const nonce = try server.auth.issueNonce();
    const header = try auth.clientResponse(server.allocator, "alice", "alicepass", nonce[0..], "INVITE", "sip:nobody@127.0.0.1:5060");
    defer server.allocator.free(header);
    var auth_line_buf: [512]u8 = undefined;
    const auth_line = std.fmt.bufPrint(&auth_line_buf, "Authorization: {s}\r\n", .{header}) catch unreachable;
    var raw_buf: [2048]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:nobody@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK404\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:nobody@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-404@127.0.0.1\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "{s}" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{auth_line}) catch unreachable;
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

test "e2e bare INVITE is challenged before lookup" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    // No Authorization at all: 401, and crucially no dialog, no forward,
    // no 404-cache entry — auth precedes everything but loop protection.
    const req = try parseRequest("INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbare401\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-bare401\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onInvite(req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get("call-bare401") == null);
    try std.testing.expect(server.txn_layer.getTransaction("z9hG4bKbare401", .INVITE) == null);
}

test "e2e INVITE with wrong password is challenged, not forwarded" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const nonce = try server.auth.issueNonce();
    const header = try auth.clientResponse(server.allocator, "alice", "wrongpass", nonce[0..], "INVITE", "sip:bob@127.0.0.1:5060");
    defer server.allocator.free(header);
    var auth_line_buf: [512]u8 = undefined;
    const auth_line = std.fmt.bufPrint(&auth_line_buf, "Authorization: {s}\r\n", .{header}) catch unreachable;
    var raw_buf: [2048]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbadpass\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-badpass\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "{s}" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{auth_line}) catch unreachable;
    try server.onInvite(try parseRequest(raw), test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get("call-badpass") == null);
}

test "e2e INVITE unknown user is challenged, never 404" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;

    // Nobody is seeded and holds no password: the bare INVITE 401s before
    // lookup, so existence never leaks (same rule as REGISTER).
    const req = try parseRequest("INVITE sip:nobody@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKunk401\r\n" ++
        "From: <sip:nobody@127.0.0.1:5060>;tag=nobodyTag\r\n" ++
        "To: <sip:nobody@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-unk401\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:nobody@127.0.0.1>\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onInvite(req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get("call-unk401") == null);
    try std.testing.expect(server.txn_layer.getTransaction("z9hG4bKunk401", .INVITE) == null);
}

test "e2e authed INVITE duplicate absorbs without re-forward" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var bob_sock = try transport.UdpSocket.init(std.testing.io, 0);
    defer bob_sock.deinit();
    const bob_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(bob_sock.socket.address.ip4.port) };

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerHandshake(&server, "bob", "bobpass", bob_addr, &resp_buf, "bobreg@127.0.0.1", 1, 3600);
    {
        var drain_buf: [1024]u8 = undefined;
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
    }

    // Timer-A style duplicate: same branch/Call-ID/CSeq, and a junk
    // Authorization that would 401 if it ever reached verification.
    const call_id = "call-dupauth";
    try inviteHandshake(&server, call_id, "z9hG4bKdupauth", test_alice_addr, false, &resp_buf, &fwd_buf);
    {
        var drain_buf: [2048]u8 = undefined;
        const fwd = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
        try std.testing.expect(std.mem.find(u8, fwd.data, "INVITE sip:bob@") != null);
    }
    const dup = try parseRequest("INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKdupauth\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-dupauth\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Authorization: Digest username=\"alice\", response=\"junk\"\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onInvite(dup, test_alice_addr, &resp_buf, &fwd_buf);

    // Absorbed: exactly one forward ever reached bob, dialog untouched.
    {
        var quiet_buf: [2048]u8 = undefined;
        const res = bob_sock.recvFromTimeout(&quiet_buf, transport.timeoutMs(300));
        try std.testing.expectError(error.Timeout, res);
    }
    try std.testing.expect(server.calls.get(call_id) != null);
}

test "e2e CANCEL then 2xx race goes to answered" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-race";
    try inviteHandshake(&server, call_id, "z9hG4bKrace", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .proceeding);

    const cancel_req = try parseRequest("CANCEL sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcancel\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-race\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onCancel(cancel_req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .canceling);

    // Callee's 2xx arrives anyway (race)
    try deliverResponse(&server, "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKrace\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-race\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .answered);
}

test "e2e CANCEL then 487 terminates and removes call" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-487";
    try inviteHandshake(&server, call_id, "z9hG4bK487", test_alice_addr, false, &resp_buf, &fwd_buf);

    const cancel_req = try parseRequest("CANCEL sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcancel2\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-487\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onCancel(cancel_req, test_alice_addr, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .canceling);

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
    try server.auth.addUser("short", "shortpass");

    var resp_buf: [4096]u8 = undefined;
    try registerHandshake(&server, "short", "shortpass", test_alice_addr, &resp_buf, "shortreg@127.0.0.1", 1, 1);
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
    try inviteHandshake(&server, call_id, "z9hG4bKrtp", test_alice_addr, true, &resp_buf, &fwd_buf);

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
    try std.testing.expectEqual(@as(u16, 4000), session.callee_rtp_port);
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
    // ACK opens the two session-owned relay sockets...
    const rtp_session = server.rtp_sessions.getSession(call_id).?;
    try std.testing.expect(rtp_session.caller_sock != null);
    try std.testing.expect(rtp_session.callee_sock != null);

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
    try server.auth.addUser("dup", "duppass");

    var resp_buf: [4096]u8 = undefined;
    try registerHandshake(&server, "dup", "duppass", test_alice_addr, &resp_buf, "dupreg@127.0.0.1", 5, 3600);
    try std.testing.expect(server.reg.lookup("sip:dup") != null);

    // Retransmission with a lower CSeq (same Call-ID) must not error.
    try registerHandshake(&server, "dup", "duppass", test_alice_addr, &resp_buf, "dupreg@127.0.0.1", 3, 3600);
    try std.testing.expect(server.reg.lookup("sip:dup") != null);
}

test "e2e REGISTER without credentials stores nothing" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    const req = try parseRequest("REGISTER sip:alice@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKnoauth\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=tagnoauth\r\n" ++
        "To: <sip:alice@127.0.0.1:5060>\r\n" ++
        "Call-ID: noauth@127.0.0.1\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    // Challenged with 401 (sent over loopback, unobserved here).
    try server.onRegister(req, test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:alice@127.0.0.1:5060") == null);
}

test "e2e REGISTER with wrong password stores nothing" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    const nonce = try server.auth.issueNonce();
    const header = try auth.clientResponse(
        server.allocator,
        "alice",
        "wrongpass",
        nonce[0..],
        "REGISTER",
        "sip:alice@127.0.0.1:5060",
    );
    defer server.allocator.free(header);

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "REGISTER sip:alice@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbadpass\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=tagbadpass\r\n" ++
        "To: <sip:alice@127.0.0.1:5060>\r\n" ++
        "Call-ID: badpass@127.0.0.1\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Authorization: {s}\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{header}) catch unreachable;

    var resp_buf: [4096]u8 = undefined;
    try server.onRegister(try parseRequest(raw), test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:alice@127.0.0.1:5060") == null);
}

test "e2e REGISTER with stale nonce stores nothing" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    const nonce = try server.auth.issueNonce();
    const past = std.Io.Timestamp.now(std.testing.io, std.Io.Clock.real).toSeconds() - auth.nonce_ttl_secs - 1;
    const entry = server.auth.nonces.getPtr(nonce[0..]).?;
    entry.* = past;

    const header = try auth.clientResponse(
        server.allocator,
        "alice",
        "alicepass",
        nonce[0..],
        "REGISTER",
        "sip:alice@127.0.0.1:5060",
    );
    defer server.allocator.free(header);

    var raw_buf: [1024]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "REGISTER sip:alice@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKstale\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=tagstale\r\n" ++
        "To: <sip:alice@127.0.0.1:5060>\r\n" ++
        "Call-ID: stale@127.0.0.1\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "Authorization: {s}\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{header}) catch unreachable;

    var resp_buf: [4096]u8 = undefined;
    try server.onRegister(try parseRequest(raw), test_alice_addr, &resp_buf);
    try std.testing.expect(server.reg.lookup("sip:alice@127.0.0.1:5060") == null);
}

test "e2e CANCEL with missing callee sends 481" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);

    // Insert a call manually in proceeding state with no callee contact
    const call_id = "call-nocallee";
    _ = try call.ensureDialog(&server.calls, server.allocator, call_id, .{ .caller_addr = test_alice_addr });

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
    try inviteHandshake(&server, call_id, "z9hG4bKtimer", test_alice_addr, false, &resp_buf, &fwd_buf);
    const dlg = server.calls.getPtr(call_id).?;
    try std.testing.expect(dlg.invite_txn != null);

    // Force the forwarded INVITE transaction overdue.
    if (dlg.invite_txn) |*t| t.next_fire_at_ms = 0;

    // handleTimeout resends over loopback UDP and backs the timer off.
    server.handleTimeout();
    const fired_txn = server.calls.getPtr(call_id).?.invite_txn.?;
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
    try inviteHandshake(&server, call_id, "z9hG4bKtimeout", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .proceeding);

    // Backdate the forwarded-INVITE transaction past 64*T1 and force it
    // overdue: the next timer pass must expire it (408 + teardown).
    const dlg = server.calls.getPtr(call_id).?;
    if (dlg.invite_txn) |*t| {
        const now_ms = std.Io.Timestamp.now(std.testing.io, std.Io.Clock.real).toMilliseconds();
        t.created_at_ms = now_ms - txn.timer_b_ms - 1;
        t.next_fire_at_ms = 0;
    }

    server.handleTimeout();

    // Caller got the 408 (verified byte-exact at the builder level);
    // the dialog is torn down.
    try std.testing.expect(server.calls.get(call_id) == null);
}

test "e2e 2xx removes the INVITE client transaction" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-2xx";
    try inviteHandshake(&server, call_id, "z9hG4bK2xx", test_alice_addr, false, &resp_buf, &fwd_buf);
    const invite_branch = server.calls.get(call_id).?.call.invite_branch.?;

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

    try std.testing.expect(server.calls.get(call_id).?.call.state == .answered);
    try std.testing.expect(server.calls.get(call_id).?.invite_txn == null);
    // Pre-answer 408 context is freed at answer time...
    const answered = server.calls.get(call_id).?.call;
    try std.testing.expect(answered.caller_via == null);
    try std.testing.expect(answered.caller_from == null);
    try std.testing.expect(answered.caller_to == null);
    // ...while the dialog lifetime fields survive.
    try std.testing.expect(answered.invite_branch != null);
}

test "e2e 486 completes the transaction and Timer D sweeps it" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-busy";
    try inviteHandshake(&server, call_id, "z9hG4bKbusy", test_alice_addr, false, &resp_buf, &fwd_buf);
    // Own the branch: handleResponse tears down the call (freeing the
    // map-owned slice) before we look the transaction up below.
    const invite_branch = try std.testing.allocator.dupe(u8, server.calls.get(call_id).?.call.invite_branch.?);
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

    // Final error: call torn down (its dialog took the cached response
    // and completion state with it).
    try std.testing.expect(server.calls.get(call_id) == null);

    // Timer D expiry on a completed dialog transaction terminates
    // silently while retaining the dialog.
    const dlg = try call.ensureDialog(&server.calls, server.allocator, "call-timerd", .{ .caller_addr = test_alice_addr });
    dlg.invite_txn = try txn.makeTransaction(dlg.arena.allocator(), 0, "z9hG4bKtimerd", .INVITE, .invite, "INVITE x\r\n\r\n", test_alice_addr);
    dlg.completeInviteTxn(0);
    if (dlg.invite_txn) |*t| t.next_fire_at_ms = 0;
    server.handleTimeout();
    const after = server.calls.get("call-timerd").?;
    try std.testing.expect(after.invite_txn.?.state == .terminated);
}

test "e2e BYE removes the INVITE client transaction" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-byetxn";
    try inviteHandshake(&server, call_id, "z9hG4bKbyetxn", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.invite_txn != null);

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
    try std.testing.expect(server.calls.get(call_id).?.invite_txn == null);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .terminated);

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

test "e2e rejected callee-BYE routes to callee and removes dialog" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    // Bob listens on an ephemeral loopback port so the rejected-BYE forward
    // is observable off the wire (fixed test_bob_addr has no socket).
    var bob_sock = try transport.UdpSocket.init(std.testing.io, 0);
    defer bob_sock.deinit();
    const bob_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(bob_sock.socket.address.ip4.port) };

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerHandshake(&server, "bob", "bobpass", bob_addr, &resp_buf, "bobreg@127.0.0.1", 1, 3600);
    {
        var drain_buf: [1024]u8 = undefined;
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
    }

    const call_id = "call-byereject";
    try inviteHandshake(&server, call_id, "z9hG4bKbyereject", test_alice_addr, false, &resp_buf, &fwd_buf);
    // Drain the forwarded INVITE so the next read sees the rejected-BYE
    // forward (bob's socket collects everything addressed to it).
    {
        var drain_buf: [1024]u8 = undefined;
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
    }

    // Callee hangs up: BYE from bob terminates at forward time, dialog kept.
    const bye_req = try parseRequest("BYE sip:alice@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbyereject1\r\n" ++
        "From: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "To: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "Call-ID: call-byereject\r\n" ++
        "CSeq: 1 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    try server.onBye(bye_req, bob_addr, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id).?.call.state == .terminated);

    // No cached INVITE response exists yet; the txn table is quiet.
    try std.testing.expect(server.calls.get(call_id).?.invite_txn == null or
        server.calls.get(call_id).?.invite_txn.?.response_buf == null);
    const txns_before = server.txn_layer.map.count();

    // Caller rejects the BYE: 403 from alice must reach bob (not bounce to
    // alice), remove the dialog, and cache nothing.
    try deliverResponse(&server, "SIP/2.0 403 Forbidden\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKbyerejectresp\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>;tag=bobTag\r\n" ++
        "Call-ID: call-byereject\r\n" ++
        "CSeq: 1 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", test_alice_addr, &fwd_buf);

    var recv_buf: [2048]u8 = undefined;
    const got = try bob_sock.recvFromTimeout(&recv_buf, transport.timeoutMs(2000));
    try std.testing.expect(std.mem.find(u8, got.data, "SIP/2.0 403") != null);
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(txns_before, server.txn_layer.map.count());
}

test "e2e forwarded INVITE carries PBX-rewritten SDP" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    // Bob listens on an ephemeral loopback port (no fixed-port conflicts).
    var bob_sock = try transport.UdpSocket.init(std.testing.io, 0);
    defer bob_sock.deinit();
    const bob_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(bob_sock.socket.address.ip4.port) };

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    // Register bob AT the listening socket so the forward reaches it.
    try registerHandshake(&server, "bob", "bobpass", bob_addr, &resp_buf, "bobreg@127.0.0.1", 1, 3600);
    // Drain bob's own handshake traffic (401 + 200) so the next read below
    // sees the forwarded INVITE.
    {
        var drain_buf: [1024]u8 = undefined;
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
        _ = try bob_sock.recvFromTimeout(&drain_buf, transport.timeoutMs(2000));
    }

    const call_id = "call-sdpfwd";
    try inviteHandshake(&server, call_id, "z9hG4bKsdpfwd", test_alice_addr, true, &resp_buf, &fwd_buf);

    // Read what the callee actually received off the wire.
    var recv_buf: [2048]u8 = undefined;
    const got = try bob_sock.recvFromTimeout(&recv_buf, transport.timeoutMs(2000));
    const fwd_req = (try parser.parse(got.data)).request;

    // SDP points at the PBX relay, not the caller's endpoint...
    const session = server.rtp_sessions.getSession(call_id).?;
    var port_buf: [32]u8 = undefined;
    const port_line = std.fmt.bufPrint(&port_buf, "m=audio {d} RTP/AVP", .{session.relay_callee_port}) catch unreachable;
    try std.testing.expect(std.mem.find(u8, fwd_req.body, port_line) != null);
    try std.testing.expect(std.mem.find(u8, fwd_req.body, "c=IN IP4 127.0.0.1") != null);
    try std.testing.expect(std.mem.find(u8, fwd_req.body, "m=audio 20000") == null);
}

test "e2e 486 retransmit replays cached error instead of re-forwarding" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    const call_id = "call-486re";
    try inviteHandshake(&server, call_id, "z9hG4bKre", test_alice_addr, false, &resp_buf, &fwd_buf);
    const invite_branch = server.calls.get(call_id).?.call.invite_branch.?;
    try std.testing.expect(server.calls.get(call_id).?.invite_txn != null);

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

    // Call torn down; only the client-branch error cache remains server-side.
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(@as(usize, 1), server.txn_layer.map.count());
    try std.testing.expect(server.txn_layer.getTransaction("z9hG4bKre", .INVITE).?.response_buf != null);

    // Caller retransmits the INVITE: replay, no re-forward, no new state.
    try inviteHandshake(&server, call_id, "z9hG4bKre", test_alice_addr, false, &resp_buf, &fwd_buf);
    try std.testing.expect(server.calls.get(call_id) == null);
    try std.testing.expectEqual(@as(usize, 1), server.txn_layer.map.count());
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

test "e2e INVITE past the dialog cap gets 503" {
    var server = try Pbx.init(std.testing.allocator, std.testing.io, 0);
    defer server.deinit();

    // Observer socket stands in for the caller so the 503 is readable.
    var caller_sock = try transport.UdpSocket.init(std.testing.io, 0);
    defer caller_sock.deinit();
    const caller_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(caller_sock.socket.address.ip4.port) };

    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    try registerUser(&server, "alice", test_alice_addr, &resp_buf);
    try registerUser(&server, "bob", test_bob_addr, &resp_buf);

    // Fill the dialog table without any SIP traffic.
    var i: usize = 0;
    while (i < call.max_dialogs) : (i += 1) {
        var id_buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "fill-{d}", .{i}) catch unreachable;
        _ = try call.ensureDialog(&server.calls, server.allocator, id, .{ .caller_addr = test_alice_addr });
    }
    try std.testing.expectEqual(call.max_dialogs, server.calls.count());

    // Authenticated (overload is checked after auth): the new call must 503
    // while the table is full.
    const nonce = try server.auth.issueNonce();
    const header = try auth.clientResponse(server.allocator, "alice", "alicepass", nonce[0..], "INVITE", "sip:bob@127.0.0.1:5060");
    defer server.allocator.free(header);
    var auth_line_buf: [512]u8 = undefined;
    const auth_line = std.fmt.bufPrint(&auth_line_buf, "Authorization: {s}\r\n", .{header}) catch unreachable;
    var cap_buf: [2048]u8 = undefined;
    const req = try parseRequest(std.fmt.bufPrint(&cap_buf, "INVITE sip:bob@127.0.0.1:5060 SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcap503\r\n" ++
        "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
        "To: <sip:bob@127.0.0.1:5060>\r\n" ++
        "Call-ID: call-cap503\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@127.0.0.1>\r\n" ++
        "{s}" ++
        "Content-Length: 0\r\n" ++
        "\r\n", .{auth_line}) catch unreachable);
    try server.onInvite(req, caller_addr, &resp_buf, &fwd_buf);

    // 503 answered on the wire; no dialog stored.
    var recv_buf: [1024]u8 = undefined;
    const got = try caller_sock.recvFromTimeout(&recv_buf, transport.timeoutMs(2000));
    try std.testing.expect(std.mem.startsWith(u8, got.data, "SIP/2.0 503"));
    try std.testing.expect(server.calls.get("call-cap503") == null);
    try std.testing.expectEqual(call.max_dialogs, server.calls.count());
}
