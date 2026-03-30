const std = @import("std");
const net = std.Io.net;
const transport = @import("transport.zig");

pub const Header = packed struct {
    csrc_count: u4,
    extension: u1,
    padding: u1,
    version: u2,
    payload_type: u7,
    marker: u1,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,

    pub fn parse(data: []const u8) !Header {
        if (data.len < 12) return error.PacketTooShort;
        const h = std.mem.bytesAsValue(Header, data[0..12]);
        var parsed = h.*;

        parsed.sequence = std.mem.bigToNative(u16, parsed.sequence);
        parsed.timestamp = std.mem.bigToNative(u32, parsed.timestamp);
        parsed.ssrc = std.mem.bigToNative(u32, parsed.ssrc);
        if (parsed.version != 2) return error.InvalidVersion;
        return parsed;
    }

    pub fn payload(self: *const Header, data: []const u8) []const u8 {
        const header_len = 12 + (self.csrc_count * 4);
        if (self.extension == 1) {
            if (header_len + 4 > data.len) return "";
            const ext_len = std.mem.bytesAsValue(u16, data[header_len + 2 ..][0..2]);
            _ = ext_len;
        }
        if (header_len > data.len) return "";
        var payload_data = data[header_len..];
        if (self.padding == 1 and payload_data.len > 0) {
            const pad_len = payload_data[payload_data.len - 1];
            if (pad_len <= payload_data.len) {
                payload_data = payload_data[0 .. payload_data.len - pad_len];
            }
        }
        return payload_data;
    }
};

pub const Session = struct {
    call_id: []u8,
    caller_rtp_port: u16,
    callee_rtp_port: u16,
    caller_ip: net.IpAddress,
    callee_ip: net.IpAddress,
    caller_payload_type: u7,
    callee_payload_type: u7,
};

pub const Manager = struct {
    sessions: std.StringHashMap(Session),
    next_port: u16,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Manager {
        return .{
            .sessions = std.StringHashMap(Session).init(allocator),
            .next_port = 10000,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Manager) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.sessions.deinit();
    }

    pub fn createSession(self: *Manager, call_id: []const u8, caller_port: u16, caller_ip: net.IpAddress, caller_pt: u7) !Session {
        if (self.next_port > 60000) self.next_port = 10000;
        const callee_port = self.next_port;
        self.next_port += 2;

        const call_id_owned = try self.allocator.dupe(u8, call_id);
        errdefer self.allocator.free(call_id_owned);

        const session = Session{
            .call_id = call_id_owned,
            .caller_rtp_port = caller_port,
            .callee_rtp_port = callee_port,
            .caller_ip = caller_ip,
            .callee_ip = undefined,
            .caller_payload_type = caller_pt,
            .callee_payload_type = 0,
        };

        try self.sessions.put(call_id_owned, session);
        return session;
    }

    pub fn getSession(self: *Manager, call_id: []const u8) ?*Session {
        return self.sessions.getPtr(call_id);
    }

    pub fn removeSession(self: *Manager, call_id: []const u8) void {
        if (self.sessions.fetchRemove(call_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }
};

pub fn handleRtpPacket(packet: []const u8, from_addr: net.IpAddress, manager: *Manager, sip_socket: *transport.UdpSocket) !void {
    _ = try Header.parse(packet);
    var it = manager.sessions.iterator();
    while (it.next()) |entry| {
        const session = entry.value_ptr;
        if (from_addr.ip4.port == session.caller_rtp_port) {
            if (session.callee_ip.ip4.port != 0) {
                std.debug.print("RTP: Forwarding from caller to callee: {} bytes\n", .{packet.len});
                try sip_socket.sendToPort(packet, session.callee_ip, session.callee_rtp_port);
                return;
            }
        } else if (from_addr.ip4.port == session.callee_rtp_port) {
            std.debug.print("RTP: Forwarding from callee to caller: {} bytes\n", .{packet.len});
            try sip_socket.sendToPort(packet, session.caller_ip, session.caller_rtp_port);
            return;
        }
    }
}

test "RTP header parse basic" {
    var buf: [12]u8 = [_]u8{0} ** 12;
    buf[0] = 0x80;
    buf[1] = 0x00;
    buf[2] = 0x12;
    buf[3] = 0x34;
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8] = 0x00;
    buf[9] = 0x00;
    buf[10] = 0x00;
    buf[11] = 0x01;

    const h = try Header.parse(&buf);
    try std.testing.expectEqual(@as(u2, 2), h.version);
    try std.testing.expectEqual(@as(u7, 0), h.payload_type);
    try std.testing.expectEqual(@as(u16, 0x1234), h.sequence);
    try std.testing.expectEqual(@as(u32, 1), h.ssrc);
}
