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
///
/// UA endpoints (caller_*/callee_*) are the real party addresses: matching
/// and forwarding always use these. relay_* are PBX-bound ports advertised
/// in rewritten SDPs; media flows UA -> PBX relay -> UA.
pub const Session = struct {
    call_id: []u8,
    caller_ip: net.IpAddress,
    /// Caller's UA media port (from its SDP). Never changes.
    caller_rtp_port: u16,
    callee_ip: net.IpAddress,
    /// Callee's UA media port (from its 200 OK SDP). 0 until answered.
    callee_rtp_port: u16,
    /// PBX-bound relay ports advertised to caller / callee respectively.
    relay_caller_port: u16,
    relay_callee_port: u16,
    /// Relay sockets, opened on ACK. Owned here: closed exactly once by
    /// removeSession/deinit, never copied elsewhere (fd discipline).
    caller_sock: ?transport.UdpSocket,
    callee_sock: ?transport.UdpSocket,
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
            if (entry.value_ptr.caller_sock) |*sock| sock.deinit();
            if (entry.value_ptr.callee_sock) |*sock| sock.deinit();
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
        const relay_caller = self.next_port;
        const relay_callee = self.next_port + 2;
        self.next_port += 4;

        const call_id_owned = try self.allocator.dupe(u8, call_id);
        errdefer self.allocator.free(call_id_owned);
        const session = Session{
            .call_id = call_id_owned,
            .caller_ip = caller_ip,
            .caller_rtp_port = caller_port,
            .callee_ip = .{ .ip4 = net.Ip4Address.unspecified(0) },
            // Unknown until the callee answers; the port-0 guard in the
            // relay path depends on this sentinel.
            .callee_rtp_port = 0,
            .relay_caller_port = relay_caller,
            .relay_callee_port = relay_callee,
            .caller_sock = null,
            .callee_sock = null,
            .caller_payload_type = caller_pt,
            .callee_payload_type = 0,
        };

        try self.sessions.put(call_id_owned, session);
        return session;
    }

    pub fn getSession(self: *Sessions, call_id: []const u8) ?*Session {
        return self.sessions.getPtr(call_id);
    }

    /// Records the caller's renegotiated media endpoint (from a re-INVITE
    /// SDP). Mirror of setCallee; relay ports and sockets are untouched.
    /// Unknown calls are ignored.
    pub fn setCaller(
        self: *Sessions,
        call_id: []const u8,
        caller_ip: net.IpAddress,
        caller_port: u16,
        caller_pt: u7,
    ) void {
        const session = self.sessions.getPtr(call_id) orelse return;
        session.caller_ip = caller_ip;
        session.caller_rtp_port = caller_port;
        session.caller_payload_type = caller_pt;
    }

    /// Records the callee's answered media endpoint (from its 200 OK SDP).
    /// Unknown calls are ignored.
    pub fn setCallee(
        self: *Sessions,
        call_id: []const u8,
        callee_ip: net.IpAddress,
        callee_port: u16,
        callee_pt: u7,
    ) void {
        const session = self.sessions.getPtr(call_id) orelse return;
        session.callee_ip = callee_ip;
        session.callee_rtp_port = callee_port;
        session.callee_payload_type = callee_pt;
    }

    /// True while any session holds open relay sockets: the run loop must
    /// wake on RTP cadence instead of sleeping to the next SIP timeout,
    /// or media sits unread in kernel buffers between SIP events.
    pub fn hasOpenRelays(self: *Sessions) bool {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const session = entry.value_ptr;
            if (session.caller_sock != null or session.callee_sock != null) return true;
        }
        return false;
    }

    pub fn removeSession(self: *Sessions, call_id: []const u8) void {
        if (self.sessions.getPtr(call_id)) |session| {
            if (session.caller_sock) |*sock| sock.deinit();
            if (session.callee_sock) |*sock| sock.deinit();
            session.caller_sock = null;
            session.callee_sock = null;
        }
        if (self.sessions.fetchRemove(call_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Polls every relay socket once (non-blocking). Routing resolves
    /// positionally per session: no scans, no borrows beyond the entry.
    pub fn drain(self: *Sessions, sip_socket: *transport.UdpSocket, rtp_buf: []u8) void {
        const poll = transport.pollTimeout();
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const session = entry.value_ptr;
            if (session.caller_sock) |*sock| {
                if (sock.recvFromTimeout(rtp_buf, poll)) |r| {
                    relayPacket(r.data, r.from, session, sip_socket) catch continue;
                } else |_| {}
            }
            if (session.callee_sock) |*sock| {
                if (sock.recvFromTimeout(rtp_buf, poll)) |r| {
                    relayPacket(r.data, r.from, session, sip_socket) catch continue;
                } else |_| {}
            }
        }
    }
};

/// Routes one RTP packet for a single session leg. Caller and callee legs
/// are matched by exact UA endpoint; anything else is dropped. No map
/// access here: the drain loop already holds the session, so routing is
/// positional (O(1), no scans, no borrow conflicts).
///
/// Forwards emanate from the destination leg's relay socket when open, so
/// replies (echo, RTCP) return to a polled socket instead of the SIP
/// socket (where they would hit the SIP parser and die). Before ACK opens
/// the sockets, early media falls back to the SIP socket one-way.
pub fn relayPacket(
    packet: []const u8,
    from: net.IpAddress,
    session: *Session,
    sip_socket: *transport.UdpSocket,
) !void {
    _ = try Header.parse(packet);
    if (std.mem.eql(u8, &from.ip4.bytes, &session.caller_ip.ip4.bytes) and
        from.ip4.port == session.caller_rtp_port)
    {
        if (session.callee_rtp_port != 0) {
            log.debug("RTP: Forwarding from caller to callee: {} bytes", .{packet.len});
            const dest = net.IpAddress{ .ip4 = net.Ip4Address{ .bytes = session.callee_ip.ip4.bytes, .port = session.callee_rtp_port } };
            if (session.callee_sock) |*sock| {
                try sock.sendTo(packet, dest);
            } else {
                try sip_socket.sendTo(packet, dest);
            }
        }
    } else if (std.mem.eql(u8, &from.ip4.bytes, &session.callee_ip.ip4.bytes) and
        from.ip4.port == session.callee_rtp_port)
    {
        log.debug("RTP: Forwarding from callee to caller: {} bytes", .{packet.len});
        const dest = net.IpAddress{ .ip4 = net.Ip4Address{ .bytes = session.caller_ip.ip4.bytes, .port = session.caller_rtp_port } };
        if (session.caller_sock) |*sock| {
            try sock.sendTo(packet, dest);
        } else {
            try sip_socket.sendTo(packet, dest);
        }
    }
}

test "RTP header parse basic" {
    var buf: [12]u8 = @splat(0);
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
    var buf: [20]u8 = @splat(0);
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
    var buf: [24]u8 = @splat(0);
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
    var buf: [18]u8 = @splat(0);
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
    try relayPacket(&packet, matching_from, session, &relay);
    var recv_buf: [64]u8 = undefined;
    const received = try dest.recvFrom(&recv_buf);
    try std.testing.expectEqual(@as(usize, 15), received.data.len);

    // Same RTP port but different IP must NOT forward (cross-talk guard)
    const wrong_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 99 }, .port = 20000 } };
    try relayPacket(&packet, wrong_ip, session, &relay);

    // A matching packet forwarded now should arrive with no extra packet ahead
    // of it: if wrong_ip had been forwarded, this receive would see that packet
    // instead of the one we just sent.
    try relayPacket(&packet, matching_from, session, &relay);
    const second = try dest.recvFrom(&recv_buf);
    try std.testing.expectEqual(@as(usize, 15), second.data.len);
    try std.testing.expectEqualStrings(&packet, second.data);
}

test "RTP relay forwards callee to caller with intact bytes" {
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    // Destination socket standing in for the caller side.
    var dest = try transport.UdpSocket.init(std.testing.io, 0);
    defer dest.deinit();
    const dest_addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(dest.socket.address.ip4.port) };

    const callee_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 20 }, .port = 5072 } };

    _ = try sessions.createSession("call-rev", dest_addr.ip4.port, dest_addr, 0);
    const session = sessions.getSession("call-rev").?;
    session.callee_ip = callee_ip;
    session.callee_rtp_port = 30000;

    var relay = try transport.UdpSocket.init(std.testing.io, 0);
    defer relay.deinit();

    const packet = [_]u8{ 0x80, 0x08, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF };

    const callee_from = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 20 }, .port = 30000 } };
    try relayPacket(&packet, callee_from, session, &relay);

    var recv_buf: [64]u8 = undefined;
    const received = try dest.recvFrom(&recv_buf);
    try std.testing.expectEqual(@as(usize, packet.len), received.data.len);
    try std.testing.expectEqualStrings(&packet, received.data);
}

test "RTP relay drops caller packet before callee SDP arrives" {
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    const caller_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5070 } };
    _ = try sessions.createSession("call-nocallee", 20000, caller_ip, 0);

    // Fresh sessions carry the unspecified sentinel, never undefined memory.
    const session = sessions.getSession("call-nocallee").?;
    try std.testing.expectEqual(@as(u16, 0), session.callee_ip.ip4.port);

    var relay = try transport.UdpSocket.init(std.testing.io, 0);
    defer relay.deinit();

    const packet = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const matching_from = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 20000 } };

    // Must return normally (no send target exists) and leave the session alone.
    try relayPacket(&packet, matching_from, session, &relay);
    try std.testing.expectEqual(@as(u16, 0), session.callee_ip.ip4.port);

    // Nothing was emitted toward the relay socket itself either.
    var recv_buf: [64]u8 = undefined;
    const res = relay.recvFromTimeout(&recv_buf, transport.pollTimeout());
    try std.testing.expectError(error.Timeout, res);
}

test "RTP relay ignores packets from unknown sources" {
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    const caller_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5070 } };
    _ = try sessions.createSession("call-unknown", 20000, caller_ip, 0);

    var relay = try transport.UdpSocket.init(std.testing.io, 0);
    defer relay.deinit();

    const packet = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const stranger = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 10, 9, 9, 9 }, .port = 9999 } };
    const session = sessions.getSession("call-unknown").?;

    try relayPacket(&packet, stranger, session, &relay);
}

test "RTP header rejects bad version and short packets" {
    var bad_version: [12]u8 = @splat(0);
    bad_version[0] = 0x00; // version 0
    try std.testing.expectError(error.InvalidVersion, Header.parse(&bad_version));

    var short: [8]u8 = @splat(0);
    short[0] = 0x80;
    try std.testing.expectError(error.PacketTooShort, Header.parse(&short));
}

test "setCallee records the answered endpoint, ignores unknown calls" {
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    const caller_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 10 }, .port = 5070 } };
    _ = try sessions.createSession("call-1", 20000, caller_ip, 0);

    // Pre-answer sentinel: unknown callee port.
    try std.testing.expectEqual(@as(u16, 0), sessions.getSession("call-1").?.callee_rtp_port);

    const callee_ip = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 192, 168, 1, 20 }, .port = 5072 } };
    sessions.setCallee("call-1", callee_ip, 4000, 8);

    const session = sessions.getSession("call-1").?;
    try std.testing.expectEqual(callee_ip, session.callee_ip);
    try std.testing.expectEqual(@as(u16, 4000), session.callee_rtp_port);
    try std.testing.expectEqual(@as(u7, 8), session.callee_payload_type);

    // Unknown call IDs are silently ignored.
    sessions.setCallee("call-missing", callee_ip, 4000, 8);
}

test "RTP relay end-to-end through session sockets, mismatched UA ports" {
    const io = std.testing.io;
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    // Two UAs on ephemeral loopback ports (deliberately different numbers,
    // and different from the PBX relay range starting at 10000).
    var caller = try transport.UdpSocket.init(io, 0);
    defer caller.deinit();
    const caller_port = caller.socket.address.ip4.port;
    var callee = try transport.UdpSocket.init(io, 0);
    defer callee.deinit();
    const callee_port = callee.socket.address.ip4.port;

    const loopback = std.Io.net.Ip4Address.loopback(0).bytes;
    const caller_ip = std.Io.net.IpAddress{ .ip4 = .{ .bytes = loopback, .port = 0 } };
    const callee_ip = std.Io.net.IpAddress{ .ip4 = .{ .bytes = loopback, .port = 0 } };

    _ = try sessions.createSession("call-e2e", caller_port, caller_ip, 0);
    sessions.setCallee("call-e2e", callee_ip, callee_port, 0);

    // Open relay sockets the way onAck does.
    const session = sessions.getSession("call-e2e").?;
    session.caller_sock = try transport.UdpSocket.init(io, session.relay_caller_port);
    session.callee_sock = try transport.UdpSocket.init(io, session.relay_callee_port);

    // Stands in for the SIP socket: source of relayed sends.
    var out = try transport.UdpSocket.init(io, 0);
    defer out.deinit();

    var rtp_buf: [256]u8 = undefined;
    var recv_buf: [256]u8 = undefined;
    const pkt1 = [_]u8{ 0x80, 0x00, 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 7, 0xAA, 0xBB };
    const pkt2 = [_]u8{ 0x80, 0x08, 0x56, 0x78, 0, 0, 0, 2, 0, 0, 0, 9, 0xCC, 0xDD };

    // Caller -> relay -> callee.
    try caller.sendTo(&pkt1, .{ .ip4 = std.Io.net.Ip4Address.loopback(session.relay_caller_port) });
    sessions.drain(&out, &rtp_buf);
    const got1 = try callee.recvFromTimeout(&recv_buf, transport.timeoutMs(2000));
    try std.testing.expectEqualStrings(&pkt1, got1.data);

    // Callee -> relay -> caller.
    try callee.sendTo(&pkt2, .{ .ip4 = std.Io.net.Ip4Address.loopback(session.relay_callee_port) });
    sessions.drain(&out, &rtp_buf);
    const got2 = try caller.recvFromTimeout(&recv_buf, transport.timeoutMs(2000));
    try std.testing.expectEqualStrings(&pkt2, got2.data);
}

test "hasOpenRelays tracks relay socket lifetime" {
    const io = std.testing.io;
    var sessions = Sessions.init(std.testing.allocator);
    defer sessions.deinit();

    try std.testing.expect(!sessions.hasOpenRelays());

    const loopback = std.Io.net.Ip4Address.loopback(0);
    _ = try sessions.createSession("call-relayq", 20000, .{ .ip4 = loopback }, 0);
    // Session exists but no sockets yet (they open on ACK): still quiet.
    try std.testing.expect(!sessions.hasOpenRelays());

    // Ephemeral sockets stand in for relay binds (no fixed ports in tests).
    const session = sessions.getSession("call-relayq").?;
    session.caller_sock = try transport.UdpSocket.init(io, 0);
    session.callee_sock = try transport.UdpSocket.init(io, 0);
    try std.testing.expect(sessions.hasOpenRelays());

    sessions.removeSession("call-relayq");
    try std.testing.expect(!sessions.hasOpenRelays());
}
