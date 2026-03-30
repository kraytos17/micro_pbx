const std = @import("std");

const reg = @import("registrar.zig");
const rtp = @import("rtp.zig");
const sdp = @import("sdp.zig");
const msg = @import("sip/message.zig");
const transport = @import("transport.zig");

pub fn handleMessage(req: msg.Request, from_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, resp_buf: []u8, fwd_data: []const u8) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    if (contact) |c| {
        try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
        try socket.sendTo(fwd_data, c.address);
    } else {
        try sendResponse(socket, from_addr, resp_buf, 404, "Not Found", req);
    }
}

pub fn handleOptions(req: msg.Request, from_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, resp_buf: []u8, fwd_buf: []u8) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    if (contact) |c| {
        try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
        const forwarded = try buildOptionsRequest(req, c.address, fwd_buf);
        try socket.sendTo(forwarded, c.address);
    } else {
        try sendResponse(socket, from_addr, resp_buf, 404, "Not Found", req);
    }
}

pub fn handleAck(req: msg.Request, dest_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, pbx_addr: std.Io.net.IpAddress, branch: []const u8, fwd_buf: []u8) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    const actual_dest = if (contact) |c| c.address else dest_addr;

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, actual_dest);
}

pub fn handleBye(req: msg.Request, dest_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, pbx_addr: std.Io.net.IpAddress, branch: []const u8, fwd_buf: []u8) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    const actual_dest = if (contact) |c| c.address else dest_addr;

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, actual_dest);
}

pub fn handleCancel(req: msg.Request, caller_addr: std.Io.net.IpAddress, callee_addr: std.Io.net.IpAddress, socket: *transport.UdpSocket, resp_buf: []u8, fwd_buf: []u8) !void {
    try sendResponse(socket, caller_addr, resp_buf, 200, "OK", req);
    const forwarded = try buildCancelRequest(req, callee_addr, fwd_buf);
    try socket.sendTo(forwarded, callee_addr);
}

fn stripTopVia(raw: []const u8, out: []u8) []u8 {
    const via_start = std.mem.indexOf(u8, raw, "Via: ") orelse {
        @memcpy(out[0..raw.len], raw);
        return out[0..raw.len];
    };
    const line_end = std.mem.indexOfPos(u8, raw, via_start, "\r\n") orelse {
        @memcpy(out[0..raw.len], raw);
        return out[0..raw.len];
    };

    const via_line_end = line_end + 2; // include \r\n
    const after_via = raw[via_line_end..];
    @memcpy(out[0..via_start], raw[0..via_start]);
    @memcpy(out[via_start..][0..after_via.len], after_via);
    return out[0 .. raw.len - (via_line_end - via_start)];
}
fn buildCancelRequest(req: msg.Request, dest_addr: std.Io.net.IpAddress, buf: []u8) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "CANCEL {s} SIP/2.0\r\n", .{req.request_uri}) catch return error.BufferTooSmall).len;

    const via_proto = if (dest_addr.ip4.port != 0) "SIP/2.0/UDP" else "SIP/2.0/UDP";
    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s} {d}.{d}.{d}.{d}:{d}\r\n", .{ via_proto, dest_addr.ip4.bytes[0], dest_addr.ip4.bytes[1], dest_addr.ip4.bytes[2], dest_addr.ip4.bytes[3], dest_addr.ip4.port }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} CANCEL\r\n", .{req.cseq_num}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    return buf[0..offset];
}

pub fn handleResponse(resp: msg.Response, caller_addr: std.Io.net.IpAddress, socket: *transport.UdpSocket, buf: []u8, rtp_manager: *rtp.Manager, allocator: std.mem.Allocator, fwd_buf: []u8) !void {
    if (resp.status_code >= 200 and resp.status_code < 300 and resp.cseq_method == .INVITE) {
        if (rtp_manager.getSession(resp.call_id)) |session| {
            if (resp.body.len > 0) {
                const callee_sdp = try sdp.parseSdp(resp.body);
                session.callee_ip = caller_addr;
                session.callee_payload_type = callee_sdp.payload_type;

                const rewritten_sdp = try sdp.rewriteSdp(resp.body, "127.0.0.1", session.callee_rtp_port, allocator);
                defer allocator.free(rewritten_sdp);

                const rewritten_buf = try buildResponseWithSdp(resp, fwd_buf, rewritten_sdp, false);
                try socket.sendTo(rewritten_buf, caller_addr);
                return;
            }
        }
    }

    const stripped = stripTopVia(buf, fwd_buf);
    try socket.sendTo(stripped, caller_addr);
}

pub fn handleInvite(req: msg.Request, from_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, pbx_addr: std.Io.net.IpAddress, resp_buf: []u8, fwd_buf: []u8, allocator: std.mem.Allocator, io: std.Io) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor) orelse {
        return try sendResponse(socket, from_addr, resp_buf, 404, "Not Found", req);
    };

    try sendResponse(socket, from_addr, resp_buf, 100, "Trying", req);
    const branch = try generateBranch(allocator, io);
    defer allocator.free(branch);

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, contact.address);
}

pub fn handleRegister(req: msg.Request, from_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, resp_buf: []u8) !void {
    const aor = extractUri(req.to);
    if (req.expires) |exp| {
        if (exp == 0) {
            registrar.unregister(aor);
            return try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
        }
    }

    const expires = req.expires orelse 3600;
    try registrar.register(aor, from_addr, expires, req.call_id, req.cseq_num);
    return try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
}

pub fn extractUri(header: []const u8) []const u8 {
    if (std.mem.find(u8, header, "<")) |start| {
        const end = std.mem.find(u8, header[start..], ">") orelse return header;
        return header[start + 1 .. start + end];
    }
    return header;
}

pub fn sendResponse(socket: *transport.UdpSocket, to: std.Io.net.IpAddress, buf: []u8, status: u16, reason: []const u8, req: msg.Request) !void {
    const response = std.fmt.bufPrint(buf, "SIP/2.0 {d} {s}\r\n", .{ status, reason }) catch return error.BufferTooSmall;

    const via_start = response.len;
    const via_line = std.fmt.bufPrint(buf[via_start..], "Via: {s}\r\n", .{req.via}) catch return error.BufferTooSmall;
    const from_start = via_start + via_line.len;
    const from_line = std.fmt.bufPrint(buf[from_start..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall;

    const to_start = from_start + from_line.len;
    const to_line = std.fmt.bufPrint(buf[to_start..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall;
    const call_start = to_start + to_line.len;
    const call_line = std.fmt.bufPrint(buf[call_start..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall;

    const cseq_start = call_start + call_line.len;
    const cseq_line = std.fmt.bufPrint(buf[cseq_start..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall;

    const contact_start = cseq_start + cseq_line.len;
    var total_len = contact_start;
    if (req.contact) |c| {
        const contact_line = std.fmt.bufPrint(buf[contact_start..], "Contact: {s}\r\n\r\n", .{c}) catch return error.BufferTooSmall;

        total_len = contact_start + contact_line.len;
    } else {
        buf[contact_start] = '\r';
        buf[contact_start + 1] = '\n';
        total_len = contact_start + 2;
    }
    try socket.sendTo(buf[0..total_len], to);
}

pub fn generateBranch(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var buf: [8]u8 = undefined;
    std.Io.random(io, &buf);
    const suffix = std.mem.readInt(u64, &buf, .little);
    return std.fmt.allocPrint(allocator, "z9hG4bK{x}", .{suffix});
}

fn buildForwardedRequest(req: msg.Request, pbx_addr: std.Io.net.IpAddress, branch: []const u8, buf: []u8) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "{s} {s} SIP/2.0\r\n", .{ req.method.toSlice(), req.request_uri }) catch return error.BufferTooSmall).len;

    const via_proto = if (pbx_addr.ip4.port != 0) "SIP/2.0/UDP" else "SIP/2.0/UDP";
    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s} {d}.{d}.{d}.{d}:{d};branch={s}\r\n", .{ via_proto, pbx_addr.ip4.bytes[0], pbx_addr.ip4.bytes[1], pbx_addr.ip4.bytes[2], pbx_addr.ip4.bytes[3], pbx_addr.ip4.port, branch }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "Max-Forwards: 70\r\n", .{}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall).len;

    if (req.contact) |c| {
        offset += (std.fmt.bufPrint(buf[offset..], "Contact: {s}\r\n", .{c}) catch return error.BufferTooSmall).len;
    }
    if (req.content_type) |ct| {
        offset += (std.fmt.bufPrint(buf[offset..], "Content-Type: {s}\r\n", .{ct}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    if (req.body.len > 0) {
        @memcpy(buf[offset..][0..req.body.len], req.body);
        offset += req.body.len;
    }
    return buf[0..offset];
}

fn buildOptionsRequest(req: msg.Request, dest_addr: std.Io.net.IpAddress, buf: []u8) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "OPTIONS {s} SIP/2.0\r\n", .{req.request_uri}) catch return error.BufferTooSmall).len;

    const via_proto = if (dest_addr.ip4.port != 0) "SIP/2.0/UDP" else "SIP/2.0/UDP";
    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s} {d}.{d}.{d}.{d}:{d}\r\n", .{ via_proto, dest_addr.ip4.bytes[0], dest_addr.ip4.bytes[1], dest_addr.ip4.bytes[2], dest_addr.ip4.bytes[3], dest_addr.ip4.port }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, MESSAGE\r\n", .{}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    return buf[0..offset];
}

fn buildResponseWithSdp(resp: msg.Response, buf: []u8, sdp_body: []const u8, include_via: bool) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "SIP/2.0 {d} {s}\r\n", .{ resp.status_code, resp.reason_phrase }) catch return error.BufferTooSmall).len;

    if (include_via) {
        offset += (std.fmt.bufPrint(buf[offset..], "Via: {s}\r\n", .{resp.via}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{resp.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}", .{resp.to}) catch return error.BufferTooSmall).len;
    if (resp.to_tag) |tag| {
        offset += (std.fmt.bufPrint(buf[offset..], ";tag={s}", .{tag}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{resp.call_id}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} {s}\r\n", .{ resp.cseq_num, resp.cseq_method.toSlice() }) catch return error.BufferTooSmall).len;

    if (resp.contact) |c| {
        offset += (std.fmt.bufPrint(buf[offset..], "Contact: {s}\r\n", .{c}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "Content-Type: application/sdp\r\n", .{}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    if (sdp_body.len > 0) {
        @memcpy(buf[offset..][0..sdp_body.len], sdp_body);
        offset += sdp_body.len;
    }
    return buf[0..offset];
}

test "extractUri with brackets" {
    const result = extractUri("Alice <sip:alice@pbx.local>;tag=xyz");
    try std.testing.expectEqualStrings("sip:alice@pbx.local", result);
}

test "extractUri without brackets" {
    const result = extractUri("sip:alice@pbx.local");
    try std.testing.expectEqualStrings("sip:alice@pbx.local", result);
}

test "extractUri from request-uri" {
    const result = extractUri("sip:bob@192.168.1.10:5060");
    try std.testing.expectEqualStrings("sip:bob@192.168.1.10:5060", result);
}

test "extractUri with IP address and port" {
    const result = extractUri("Bob <sip:192.168.1.100:5070>");
    try std.testing.expectEqualStrings("sip:192.168.1.100:5070", result);
}

test "extractUri edge case - no angle brackets but has semicolon" {
    const result = extractUri("sip:alice@pbx.local;transport=udp");
    try std.testing.expectEqualStrings("sip:alice@pbx.local;transport=udp", result);
}
