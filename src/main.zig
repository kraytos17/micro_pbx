//! PBX entry point: UDP event loop dispatching SIP requests and responses.

const std = @import("std");
const transport = @import("transport.zig");
const sip = @import("sip/message.zig");
const parser = @import("sip/parser.zig");
const registrar = @import("registrar.zig");
const proxy = @import("proxy.zig");
const rtp = @import("rtp.zig");
const call = @import("call.zig");
const txn = @import("sip/transaction.zig");

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();
    const io = init.io;
    var socket = try transport.UdpSocket.init(io, 5060);
    defer socket.deinit();

    var reg = registrar.Registrar.init(alloc, io);
    defer reg.deinit();

    var txn_layer = txn.TransactionLayer.init(alloc, io);
    defer txn_layer.deinit();

    var calls = std.StringHashMap(call.Call).init(alloc);
    defer {
        var it = calls.iterator();
        while (it.next()) |kv| {
            alloc.free(kv.key_ptr.*);
            if (kv.value_ptr.*.invite_branch) |b| alloc.free(b);
        }
        calls.deinit();
    }

    var rtp_sessions = rtp.Sessions.init(alloc);
    defer rtp_sessions.deinit();

    var rtp_sockets = std.ArrayList(transport.UdpSocket).initCapacity(alloc, 32) catch unreachable;
    defer {
        for (rtp_sockets.items) |*sock| {
            sock.deinit();
        }
        rtp_sockets.deinit(alloc);
    }

    std.log.info("PBX listening on 0.0.0.0:5060", .{});
    const pbx_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5060 } };

    var recv_buf: [4096]u8 = undefined;
    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    var rtp_buf: [2048]u8 = undefined;
    while (true) {
        for (rtp_sockets.items) |*rtp_sock| {
            const result = rtp_sock.recvFrom(&rtp_buf) catch continue;
            rtp.handleRtpPacket(result.data, result.from, &rtp_sessions, &socket) catch continue;
        }

        const result = socket.recvFrom(&recv_buf) catch |err| {
            std.log.err("recvFrom error: {}", .{err});
            continue;
        };

        std.debug.print("--- Received {} bytes ---\n", .{result.data.len});
        const message = parser.parse(result.data) catch |err| {
            std.log.warn("parse error: {}", .{err});
            continue;
        };

        switch (message) {
            .request => |req| {
                std.debug.print("SIP REQUEST: {s} to {s}\n", .{ req.method.toSlice(), req.request_uri });
                switch (req.method) {
                    .REGISTER => {
                        proxy.handleRegister(req, result.from, &reg, &socket, &resp_buf) catch |err| {
                            std.log.err("handleRegister error: {}", .{err});
                        };
                    },
                    .INVITE => {
                        var arena = std.heap.ArenaAllocator.init(alloc);
                        defer arena.deinit();

                        const txn_id: txn.TransactionId = .{ .branch = req.via_branch, .method = .INVITE };
                        if (txn_layer.isRetransmission(txn_id)) {
                            std.log.info("INVITE retransmission detected for branch {s}", .{req.via_branch});
                            if (txn_layer.getTransaction(req.via_branch, .INVITE)) |existing_txn| {
                                if (existing_txn.response_buf) |cached_resp| {
                                    try socket.sendTo(cached_resp, result.from);
                                    continue;
                                }
                            }
                        }

                        var call_ctx: call.Call = if (calls.get(req.call_id)) |existing| existing else .{ .caller_addr = result.from };

                        try call.putCall(&calls, alloc, req.call_id, call_ctx);
                        if (call_ctx.state == .proceeding and call_ctx.callee_contact_addr == null) {
                            const dest_aor = proxy.extractUri(req.request_uri);
                            const contact = reg.lookup(dest_aor) orelse {
                                // Generate branch for 404 response (RFC 3261)
                                const branch_404 = try proxy.generateBranch(alloc, io);
                                defer alloc.free(branch_404);

                                // Build 404 response
                                var response_buf: [2048]u8 = undefined;
                                const response_404 = try proxy.buildResponse(&response_buf, 404, "Not Found", req, branch_404);

                                // Send the 404
                                try proxy.sendResponseWithBranch(&socket, result.from, &resp_buf, 404, "Not Found", req, branch_404);

                                // Cache the 404 response for retransmissions using client's branch
                                try txn_layer.createNonInviteTransaction(req.via_branch, .INVITE, response_404, result.from);
                                try txn_layer.storeResponse(req.via_branch, .INVITE, response_404);

                                continue;
                            };

                            call_ctx.callee_contact_addr = contact.address;

                            const invite_result = proxy.handleInvite(req, result.from, &reg, &socket, pbx_addr, &resp_buf, &fwd_buf, arena.allocator(), io) catch |err| {
                                std.log.err("handleInvite error: {}", .{err});
                                continue;
                            };

                            try txn_layer.createInviteTransaction(invite_result.branch, invite_result.forwarded, contact.address);

                            if (call_ctx.invite_branch) |old| alloc.free(old);
                            call_ctx.invite_branch = alloc.dupe(u8, invite_result.branch) catch null;
                            arena.allocator().free(invite_result.branch);
                            try call.putCall(&calls, alloc, req.call_id, call_ctx);
                        } else {
                            try proxy.sendResponse(&socket, result.from, &resp_buf, 100, "Trying", req);
                        }
                    },
                    .ACK => {
                        if (calls.getPtr(req.call_id)) |call_ctx| {
                            if (call_ctx.state == .answered) {
                                call_ctx.state = .established;
                            }

                            const dest_addr = call_ctx.callee_contact_addr orelse call_ctx.caller_addr;
                            const branch = try proxy.generateBranch(gpa.allocator(), io);
                            defer gpa.allocator().free(branch);
                            proxy.handleAck(req, dest_addr, &reg, &socket, pbx_addr, branch, &fwd_buf) catch |err| {
                                std.log.err("handleAck error: {}", .{err});
                            };

                            if (rtp_sessions.getSession(req.call_id)) |session| {
                                const caller_socket = try transport.UdpSocket.init(io, session.caller_rtp_port);
                                try rtp_sockets.append(alloc, caller_socket);
                                const callee_socket = try transport.UdpSocket.init(io, session.callee_rtp_port);
                                try rtp_sockets.append(alloc, callee_socket);
                            }
                        } else {
                            const branch = try proxy.generateBranch(gpa.allocator(), io);
                            defer gpa.allocator().free(branch);
                            proxy.handleAck(req, result.from, &reg, &socket, pbx_addr, branch, &fwd_buf) catch |err| {
                                std.log.err("handleAck error: {}", .{err});
                            };
                        }
                    },
                    .BYE => {
                        const branch = try proxy.generateBranch(gpa.allocator(), io);
                        defer gpa.allocator().free(branch);

                        if (calls.getPtr(req.call_id)) |call_ctx| {
                            const is_from_caller = call.addressEqual(result.from, call_ctx.caller_addr);
                            const dest_addr = if (is_from_caller)
                                call_ctx.callee_contact_addr orelse result.from
                            else
                                call_ctx.caller_addr;

                            call_ctx.state = .terminated;
                            proxy.handleBye(req, dest_addr, &reg, &socket, pbx_addr, branch, &fwd_buf) catch |err| {
                                std.log.err("handleBye error: {}", .{err});
                            };
                            call.removeCall(&calls, alloc, req.call_id);
                            rtp_sessions.removeSession(req.call_id);
                        } else {
                            proxy.sendResponse(&socket, result.from, &resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
                        }
                    },
                    .MESSAGE => {
                        proxy.handleMessage(req, result.from, &reg, &socket, &resp_buf, &fwd_buf) catch |err| {
                            std.log.err("handleMessage error: {}", .{err});
                        };
                    },
                    .OPTIONS => {
                        proxy.handleOptions(req, result.from, &reg, &socket, &resp_buf, &recv_buf) catch |err| {
                            std.log.err("handleOptions error: {}", .{err});
                        };
                    },
                    .CANCEL => {
                        if (calls.getPtr(req.call_id)) |call_ctx| {
                            if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                                call_ctx.state = .canceling;
                                const callee = call_ctx.callee_contact_addr orelse {
                                    std.log.warn("CANCEL for call with no callee_contact_addr", .{});
                                    continue;
                                };

                                const branch = call_ctx.invite_branch orelse {
                                    std.log.warn("CANCEL for call with no stored invite_branch", .{});
                                    continue;
                                };

                                proxy.handleCancel(req, result.from, callee, pbx_addr, branch, &socket, &resp_buf, &fwd_buf) catch |err| {
                                    std.log.err("handleCancel error: {}", .{err});
                                };
                            } else {
                                proxy.sendResponse(&socket, result.from, &resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
                            }
                        } else {
                            proxy.sendResponse(&socket, result.from, &resp_buf, 481, "Call Leg Does Not Exist", req) catch {};
                        }
                    },
                }
            },
            .response => |resp| {
                std.debug.print("SIP RESPONSE: {} {s}\n", .{ resp.status_code, resp.reason_phrase });
                const dest_addr = if (calls.get(resp.call_id)) |c| c.caller_addr else result.from;
                if (calls.getPtr(resp.call_id)) |call_ctx| {
                    switch (resp.status_code) {
                        100 => {},
                        101...199 => {
                            if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                                call_ctx.state = .ringing;
                                call_ctx.callee_resp_addr = result.from;
                                proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                    std.log.err("handleResponse 1xx: {}", .{err});
                                };
                            }
                        },
                        200...299 => {
                            if (resp.cseq_method == .INVITE) {
                                if (call_ctx.state == .proceeding or call_ctx.state == .ringing) {
                                    call_ctx.state = .answered;
                                    call_ctx.callee_resp_addr = result.from;
                                    proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                        std.log.err("handleResponse 2xx: {}", .{err});
                                    };
                                } else if (call_ctx.state == .canceling) {
                                    call_ctx.state = .answered;
                                    call_ctx.callee_resp_addr = result.from;
                                    proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                        std.log.err("handleResponse 2xx race: {}", .{err});
                                    };
                                }
                            } else {
                                proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                    std.log.err("handleResponse non-invite: {}", .{err});
                                };
                            }
                        },
                        487 => {
                            if (call_ctx.state == .canceling) {
                                call_ctx.state = .terminated;
                                proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                    std.log.err("handleResponse 487: {}", .{err});
                                };
                                call.removeCall(&calls, alloc, resp.call_id);
                            }
                        },
                        else => {
                            if (call_ctx.state != .terminated) {
                                call_ctx.state = .terminated;
                                proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                                    std.log.err("handleResponse final: {}", .{err});
                                };
                                call.removeCall(&calls, alloc, resp.call_id);
                            }
                        },
                    }
                } else {
                    proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_sessions, alloc, &fwd_buf) catch |err| {
                        std.log.err("handleResponse no-ctx: {}", .{err});
                    };
                }
            },
        }
    }
}

test {
    std.testing.refAllDecls(@This());
}
