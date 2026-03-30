const std = @import("std");
const transport = @import("transport.zig");
const sip = @import("sip/message.zig");
const parser = @import("sip/parser.zig");
const registrar = @import("registrar.zig");
const proxy = @import("proxy.zig");
const rtp = @import("rtp.zig");

const Call = struct {
    caller_addr: std.Io.net.IpAddress,
    callee_addr: ?std.Io.net.IpAddress = null,
    callee_contact_addr: ?std.Io.net.IpAddress = null,
    invite_forwarded: bool = false,
    responded: bool = false,
    canceled: bool = false,
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();
    const io = init.io;
    var socket = try transport.UdpSocket.init(io, 5060);
    defer socket.deinit();

    var reg = registrar.Registrar.init(alloc, io);
    defer reg.deinit();

    var calls = std.StringHashMap(Call).init(alloc);
    defer calls.deinit();

    var rtp_manager = rtp.Manager.init(alloc);
    defer rtp_manager.deinit();

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
            rtp.handleRtpPacket(result.data, result.from, &rtp_manager, &socket) catch continue;
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

                        var call_ctx: Call = if (calls.get(req.call_id)) |existing| existing else .{ .caller_addr = result.from };
                        if (!call_ctx.invite_forwarded) {
                            call_ctx.invite_forwarded = true;
                            const dest_aor = proxy.extractUri(req.request_uri);
                            const contact = reg.lookup(dest_aor) orelse {
                                return try proxy.sendResponse(&socket, result.from, &resp_buf, 404, "Not Found", req);
                            };

                            call_ctx.callee_contact_addr = contact.address;
                            proxy.handleInvite(req, result.from, &reg, &socket, pbx_addr, &resp_buf, &fwd_buf, arena.allocator(), io) catch |err| {
                                std.log.err("handleInvite error: {}", .{err});
                            };
                        }
                        try calls.put(req.call_id, call_ctx);
                    },
                    .ACK => {
                        const call = calls.get(req.call_id);
                        const dest_addr = if (call) |c| c.callee_contact_addr orelse c.caller_addr else result.from;
                        const branch = try proxy.generateBranch(gpa.allocator(), io);
                        defer gpa.allocator().free(branch);
                        proxy.handleAck(req, dest_addr, &reg, &socket, pbx_addr, branch, &fwd_buf) catch |err| {
                            std.log.err("handleAck error: {}", .{err});
                        };

                        if (call != null) {
                            if (rtp_manager.getSession(req.call_id)) |session| {
                                const caller_socket = try transport.UdpSocket.init(io, session.caller_rtp_port);
                                try rtp_sockets.append(alloc, caller_socket);
                                const callee_socket = try transport.UdpSocket.init(io, session.callee_rtp_port);
                                try rtp_sockets.append(alloc, callee_socket);
                            }
                        }
                    },
                    .BYE => {
                        const call = calls.get(req.call_id);
                        const dest_addr = if (call) |c| c.callee_contact_addr orelse c.caller_addr else result.from;
                        const branch = try proxy.generateBranch(gpa.allocator(), io);
                        defer gpa.allocator().free(branch);
                        _ = calls.remove(req.call_id);
                        proxy.handleBye(req, dest_addr, &reg, &socket, pbx_addr, branch, &fwd_buf) catch |err| {
                            std.log.err("handleBye error: {}", .{err});
                        };
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
                        const call = calls.get(req.call_id);
                        const dest_addr = if (call) |c| c.callee_addr orelse c.caller_addr else result.from;
                        if (calls.getPtr(req.call_id)) |c| c.canceled = true;
                        proxy.handleCancel(req, result.from, dest_addr, &socket, &resp_buf, &fwd_buf) catch |err| {
                            std.log.err("handleCancel error: {}", .{err});
                        };
                    },
                }
            },
            .response => |resp| {
                std.debug.print("SIP RESPONSE: {} {s}\n", .{ resp.status_code, resp.reason_phrase });
                const caller = calls.get(resp.call_id);
                const dest_addr = if (caller) |c| c.caller_addr else result.from;
                if (resp.status_code >= 200 and resp.status_code < 300 and caller != null) {
                    if (calls.getPtr(resp.call_id)) |call| {
                        call.callee_addr = result.from;
                    }
                }
                if (calls.getPtr(resp.call_id)) |call| {
                    if (call.responded or call.canceled) continue;
                    if (resp.status_code >= 200) call.responded = true;
                }

                proxy.handleResponse(resp, dest_addr, &socket, result.data, &rtp_manager, alloc, &fwd_buf) catch |err| {
                    std.log.err("handleResponse error: {}", .{err});
                };
            },
        }
    }
}

test {
    std.testing.refAllDecls(@This());
}
