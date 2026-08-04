//! RTP header parsing and media session management for media relay.

const std = @import("std");
const net = std.Io.net;
const transport = @import("transport.zig");

const log = std.log.scoped(.rtp);

/// Parsed RTP packet header.
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
        var header_len: usize = 12 + (self.csrc_count * 4);
        if (self.extension == 1) {
            if (header_len + 4 > data.len) return "";
            const ext_words = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, data[header_len + 2 ..][0..2]).*);
            header_len += 4 + (@as(usize, ext_words) * 4);
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

/// One active media leg, keyed by SIP Call-ID.
pub const Session = struct {
    call_id: []u8,
    caller_rtp_port: u16,
    callee_rtp_port: u16,
    caller_ip: net.IpAddress,
    callee_ip: net.IpAddress,
    caller_payload_type: u7,
    callee_payload_type: u7,
};

/// Allocates and tracks RTP sessions and their relay ports.
pub const Sessions = struct {
    sessions: std.StringHashMap(Session),
    next_port: u16,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Sessions {
        return .{
            .sessions = std.StringHashMap(Session).init(allocator),
            .next_port = 10000,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Sessions) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.sessions.deinit();
    }

    pub fn createSession(
        self: *Sessions,
        call_id: []const u8,
        caller_port: u16,
        caller_ip: net.IpAddress,
        caller_pt: u7,
    ) !Session {
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

    pub fn getSession(self: *Sessions, call_id: []const u8) ?*Session {
        return self.sessions.getPtr(call_id);
    }

    pub fn removeSession(self: *Sessions, call_id: []const u8) void {
        if (self.sessions.fetchRemove(call_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }
};

/// Forwards an RTP packet between the two parties of a matching session.
pub fn handleRtpPacket(
    packet: []const u8,
    from_addr: net.IpAddress,
    sessions: *Sessions,
    sip_socket: *transport.UdpSocket,
) !void {
    _ = try Header.parse(packet);
    var it = sessions.sessions.iterator();
    while (it.next()) |entry| {
        const session = entry.value_ptr;
        if (std.mem.eql(u8, &from_addr.ip4.bytes, &session.caller_ip.ip4.bytes) and
            from_addr.ip4.port == session.caller_rtp_port)
        {
            if (session.callee_ip.ip4.port != 0) {
                log.debug("RTP: Forwarding from caller to callee: {} bytes", .{packet.len});
                try sip_socket.sendToPort(packet, session.callee_ip, session.callee_rtp_port);
                return;
            }
        } else if (std.mem.eql(u8, &from_addr.ip4.bytes, &session.callee_ip.ip4.bytes) and
            from_addr.ip4.port == session.callee_rtp_port)
        {
            log.debug("RTP: Forwarding from callee to caller: {} bytes", .{packet.len});
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

test "RTP payload with extension header skips extension bytes" {
    // Version 2, X=1, no CSRC, PT=0
    // 12-byte header, then 4-byte ext header (ext len = 1 word), then 4 ext bytes, then 4 payload bytes
    var buf: [20]u8 = [_]u8{0} ** 20;
    buf[0] = 0x90; // V=2, X=1
    buf[1] = 0x00;
    buf[2] = 0x12;
    buf[3] = 0x34;
    buf[8] = 0x00;
    buf[9] = 0x01;
    buf[10] = 0x00;
    buf[11] = 0x00;

    // extension header: profile (2 bytes) + length in 32-bit words (big-endian 0x0001)
    buf[12] = 0xBE;
    buf[13] = 0xDE;
    buf[14] = 0x00;
    buf[15] = 0x01;

    // 4 bytes of extension data
    buf[16] = 0xAA;
    buf[17] = 0xBB;
    buf[18] = 0xCC;
    buf[19] = 0xDD;

    const h = try Header.parse(buf[0..12]);
    try std.testing.expectEqual(@as(u1, 1), h.extension);
    const payload = h.payload(&buf);
    try std.testing.expectEqual(@as(usize, 0), payload.len);
}

test "RTP payload with extension returns trailing payload" {
    var buf: [24]u8 = [_]u8{0} ** 24;
    buf[0] = 0x90; // V=2, X=1
    buf[1] = 0x00;
    buf[2] = 0x12;
    buf[3] = 0x34;
    buf[8] = 0x00;
    buf[9] = 0x01;
    buf[10] = 0x00;
    buf[11] = 0x00;

    // ext header: length = 1 word
    buf[12] = 0xBE;
    buf[13] = 0xDE;
    buf[14] = 0x00;
    buf[15] = 0x01;

    // 4 bytes extension data
    buf[16] = 0xAA;
    buf[17] = 0xBB;
    buf[18] = 0xCC;
    buf[19] = 0xDD;

    // 4 bytes of actual payload
    buf[20] = 0x11;
    buf[21] = 0x22;
    buf[22] = 0x33;
    buf[23] = 0x44;

    const h = try Header.parse(buf[0..12]);
    const payload = h.payload(&buf);
    try std.testing.expectEqual(@as(usize, 4), payload.len);
    try std.testing.expectEqualStrings(&.{ 0x11, 0x22, 0x33, 0x44 }, payload);
}

test "RTP payload strips padding" {
    // V=2, P=1, no extension, no CSRC
    // 12-byte header + 4 payload bytes + 2 pad bytes (last byte = pad length)
    var buf: [18]u8 = [_]u8{0} ** 18;
    buf[0] = 0xA0; // V=2, P=1
    buf[1] = 0x00;
    buf[2] = 0x12;
    buf[3] = 0x34;
    buf[8] = 0x00;
    buf[9] = 0x01;
    buf[10] = 0x00;
    buf[11] = 0x00;

    buf[12] = 0x11;
    buf[13] = 0x22;
    buf[14] = 0x33;
    buf[15] = 0x44;
    buf[16] = 0x00;
    buf[17] = 0x02; // pad length = 2

    const h = try Header.parse(buf[0..12]);
    const payload = h.payload(&buf);
    try std.testing.expectEqual(@as(usize, 4), payload.len);
    try std.testing.expectEqualStrings(&.{ 0x11, 0x22, 0x33, 0x44 }, payload);
}

test "RTP relay matches by IP and port, not port alone" {
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    const caller_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5070 } };

    _ = try sessions.createSession("call-1", 20000, caller_ip, 0);
    const session = sessions.getSession("call-1").?;

    // Destination socket that should receive the forwarded packet
    var dest = try transport.UdpSocket.init(std.testing.io, 0);
    defer dest.deinit();
    const dest_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(dest.socket.address.ip4.port) };
    session.callee_ip = dest_addr;
    session.callee_rtp_port = dest_addr.ip4.port;

    var relay = try transport.UdpSocket.init(std.testing.io, 0);
    defer relay.deinit();

    const packet = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 };

    // Matching (IP, port) forwards the packet
    const matching_from = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 20000 } };
    try handleRtpPacket(&packet, matching_from, &sessions, &relay);
    var recv_buf: [64]u8 = undefined;
    const received = try dest.recvFrom(&recv_buf);
    try std.testing.expectEqual(@as(usize, 15), received.data.len);

    // Same RTP port but different IP must NOT forward (cross-talk guard)
    const wrong_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 99 }, .port = 20000 } };
    try handleRtpPacket(&packet, wrong_ip, &sessions, &relay);

    // A matching packet forwarded now should arrive with no extra packet ahead
    // of it: if wrong_ip had been forwarded, this receive would see that packet
    // instead of the one we just sent.
    try handleRtpPacket(&packet, matching_from, &sessions, &relay);
    const second = try dest.recvFrom(&recv_buf);
    try std.testing.expectEqual(@as(usize, 15), second.data.len);
    try std.testing.expectEqualStrings(&packet, second.data);
}
