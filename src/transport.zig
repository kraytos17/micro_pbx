//! Thin wrapper around the std UDP socket for SIP/RTP I/O.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const log = std.log.scoped(.transport);

/// Errors returned by UDP socket operations.
pub const TransportError = error{
    SocketBindFailed,
    SendFailed,
    PacketTooLarge,
};

/// Zero-duration timeout: turns a receive into a non-blocking poll.
pub fn pollTimeout() Io.Timeout {
    return .{ .duration = .{ .raw = .zero, .clock = .real } };
}

/// Timeout `ms` milliseconds from now.
pub fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(ms), .clock = .real } };
}

/// A bound UDP socket with receive/send helpers.
pub const UdpSocket = struct {
    socket: net.Socket,
    io: Io,

    pub fn init(io: Io, port: u16) !UdpSocket {
        const addr = net.IpAddress{ .ip4 = net.Ip4Address.unspecified(port) };
        const socket = addr.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        }) catch return error.SocketBindFailed;

        return .{ .socket = socket, .io = io };
    }

    pub fn deinit(self: *UdpSocket) void {
        self.socket.close(self.io);
    }

    pub fn recvFrom(self: *UdpSocket, buf: []u8) !struct { data: []u8, from: net.IpAddress } {
        const message = self.socket.receive(self.io, buf) catch |err| {
            return err;
        };
        return .{ .data = message.data, .from = message.from };
    }

    pub fn recvFromTimeout(self: *UdpSocket, buf: []u8, timeout: Io.Timeout) !struct { data: []u8, from: net.IpAddress } {
        const message = try self.socket.receiveTimeout(self.io, buf, timeout);
        return .{ .data = message.data, .from = message.from };
    }

    pub fn sendTo(self: *UdpSocket, buf: []const u8, to: net.IpAddress) !void {
        self.socket.send(self.io, &to, buf) catch |err| switch (err) {
            error.MessageOversize => return error.PacketTooLarge,
            else => return error.SendFailed,
        };
    }

    pub fn sendToPort(self: *UdpSocket, buf: []const u8, ip: net.IpAddress, port: u16) !void {
        const addr = net.IpAddress{ .ip4 = net.Ip4Address{ .bytes = ip.ip4.bytes, .port = port } };
        try self.sendTo(buf, addr);
    }
};

test "UdpSocket init and deinit" {
    const io = std.testing.io;
    var socket = try UdpSocket.init(io, 0);
    defer socket.deinit();
}

test "UdpSocket send and receive loopback" {
    const io = std.testing.io;

    var sender = try UdpSocket.init(io, 0);
    defer sender.deinit();

    var receiver = try UdpSocket.init(io, 0);
    defer receiver.deinit();

    const receiver_addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(receiver.socket.address.ip4.port) };
    const test_data = "Hello UDP";
    try sender.sendTo(test_data, receiver_addr);

    var buf: [1024]u8 = undefined;
    const result = try receiver.recvFrom(&buf);

    try std.testing.expectEqualStrings(test_data, result.data);
}

test "recvFromTimeout with zero duration polls without blocking" {
    const io = std.testing.io;

    var socket = try UdpSocket.init(io, 0);
    defer socket.deinit();

    var buf: [1024]u8 = undefined;
    const result = socket.recvFromTimeout(&buf, pollTimeout());
    try std.testing.expectError(error.Timeout, result);
}

test "recvFromTimeout receives loopback datagram" {
    const io = std.testing.io;

    var sender = try UdpSocket.init(io, 0);
    defer sender.deinit();

    var receiver = try UdpSocket.init(io, 0);
    defer receiver.deinit();

    const receiver_addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(receiver.socket.address.ip4.port) };
    const test_data = "Hello timeout";
    try sender.sendTo(test_data, receiver_addr);

    var buf: [1024]u8 = undefined;
    const result = try receiver.recvFromTimeout(&buf, timeoutMs(2000));

    try std.testing.expectEqualStrings(test_data, result.data);
}
