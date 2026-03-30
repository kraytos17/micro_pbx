const std = @import("std");
const transport = @import("transport.zig");
const sip = @import("sip/message.zig");
const parser = @import("sip/parser.zig");
const registrar = @import("registrar.zig");
const proxy = @import("proxy.zig");

const CallContext = struct {
    caller_addr: std.Io.net.IpAddress,
    callee_addr: ?std.Io.net.IpAddress = null,
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    const io = init.io;
    var socket = try transport.UdpSocket.init(io, 5060);
    defer socket.deinit();

    var reg = registrar.Registrar.init(gpa.allocator(), io);
    defer reg.deinit();

    var calls = std.StringHashMap(CallContext).init(gpa.allocator());
    defer calls.deinit();

    std.log.info("PBX listening on 0.0.0.0:5060", .{});

    var recv_buf: [4096]u8 = undefined;
    var resp_buf: [4096]u8 = undefined;
    var fwd_buf: [4096]u8 = undefined;
    while (true) {
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
                        var arena = std.heap.ArenaAllocator.init(gpa.allocator());
                        defer arena.deinit();
                        const pbx_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5060 } };

                        try calls.put(req.call_id, .{ .caller_addr = result.from });

                        proxy.handleInvite(req, result.from, &reg, &socket, pbx_addr, &resp_buf, &fwd_buf, arena.allocator(), io) catch |err| {
                            std.log.err("handleInvite error: {}", .{err});
                        };
                    },
                    .ACK => {
                        const call = calls.get(req.call_id);
                        const dest_addr = if (call) |c| c.callee_addr orelse c.caller_addr else result.from;
                        proxy.handleAck(req, dest_addr, &reg, &socket, &recv_buf) catch |err| {
                            std.log.err("handleAck error: {}", .{err});
                        };
                    },
                    .BYE => {
                        const call = calls.get(req.call_id);
                        const dest_addr = if (call) |c| c.callee_addr orelse c.caller_addr else result.from;
                        _ = calls.remove(req.call_id);
                        proxy.handleBye(req, dest_addr, &reg, &socket, &recv_buf) catch |err| {
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
                        const dest_addr = if (call) |c| c.caller_addr else result.from;
                        _ = calls.remove(req.call_id);
                        proxy.handleCancel(req, dest_addr, &reg, &socket, &resp_buf, &fwd_buf) catch |err| {
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

                proxy.handleResponse(resp, dest_addr, &socket, result.data) catch |err| {
                    std.log.err("handleResponse error: {}", .{err});
                };
            },
        }
    }
}

test {
    std.testing.refAllDecls(@This());
}
