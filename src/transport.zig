const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

pub const TransportError = error{
    SocketBindFailed,
    SendFailed,
    PacketTooLarge,
};

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

    pub fn sendTo(self: *UdpSocket, buf: []const u8, to: net.IpAddress) !void {
        self.socket.send(self.io, &to, buf) catch return error.SendFailed;
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
