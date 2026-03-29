const std = @import("std");
const transport = @import("transport.zig");

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const io = init.io;
    var socket = try transport.UdpSocket.init(io, 5060);
    defer socket.deinit();

    std.log.info("PBX listening on 0.0.0.0:5060", .{});

    var recv_buf: [4096]u8 = undefined;
    while (true) {
        const result = socket.recvFrom(&recv_buf) catch |err| {
            std.log.err("recvFrom error: {}", .{err});
            continue;
        };

        std.log.info("Received {} bytes from {}", .{ result.data.len, result.from });

        std.debug.print("--- Packet ({d} bytes) ---\n", .{result.data.len});
        std.debug.print("{s}\n", .{result.data});
        std.debug.print("--- End packet ---\n", .{});

        socket.sendTo(result.data, result.from) catch |err| {
            std.log.err("sendTo error: {}", .{err});
        };
    }
}
