//! SIP request/response handling and message building for proxying.

const std = @import("std");

const reg = @import("registrar.zig");
const rtp = @import("rtp.zig");
const sdp = @import("sdp.zig");
const msg = @import("sip/message.zig");
const transport = @import("transport.zig");

const log = std.log.scoped(.proxy);

/// Handles a MESSAGE request, forwarding it if the destination is registered.
pub fn handleMessage(
    req: msg.Request,
    from_addr: std.Io.net.IpAddress,
    registrar: *reg.Registrar,
    socket: *transport.UdpSocket,
    resp_buf: []u8,
    fwd_data: []const u8,
) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    if (contact) |c| {
        try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
        try socket.sendTo(fwd_data, c.address);
    } else {
        try sendResponse(socket, from_addr, resp_buf, 404, "Not Found", req);
    }
}

/// Handles an OPTIONS request, responding 200 or 404 based on registration.
pub fn handleOptions(
    req: msg.Request,
    from_addr: std.Io.net.IpAddress,
    registrar: *reg.Registrar,
    socket: *transport.UdpSocket,
    resp_buf: []u8,
    fwd_buf: []u8,
) !void {
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

pub fn handleAck(
    req: msg.Request,
    dest_addr: std.Io.net.IpAddress,
    registrar: *reg.Registrar,
    socket: *transport.UdpSocket,
    pbx_addr: std.Io.net.IpAddress,
    branch: []const u8,
    fwd_buf: []u8,
) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    const actual_dest = if (contact) |c| c.address else dest_addr;

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, actual_dest);
}

pub fn handleBye(
    req: msg.Request,
    dest_addr: std.Io.net.IpAddress,
    registrar: *reg.Registrar,
    socket: *transport.UdpSocket,
    pbx_addr: std.Io.net.IpAddress,
    branch: []const u8,
    fwd_buf: []u8,
) !void {
    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    const actual_dest = if (contact) |c| c.address else dest_addr;

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, actual_dest);
}

pub fn handleCancel(
    req: msg.Request,
    caller_addr: std.Io.net.IpAddress,
    callee_addr: std.Io.net.IpAddress,
    pbx_addr: std.Io.net.IpAddress,
    invite_branch: []const u8,
    socket: *transport.UdpSocket,
    resp_buf: []u8,
    fwd_buf: []u8,
) !void {
    try sendResponse(socket, caller_addr, resp_buf, 200, "OK", req);
    const forwarded = try buildCancelRequest(req, pbx_addr, invite_branch, fwd_buf);
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

fn buildCancelRequest(
    req: msg.Request,
    pbx_addr: std.Io.net.IpAddress,
    invite_branch: []const u8,
    buf: []u8,
) ![]u8 {
    var offset: usize = 0;

    offset += (std.fmt.bufPrint(buf[offset..], "CANCEL {s} SIP/2.0\r\n", .{req.request_uri}) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "Via: SIP/2.0/UDP {d}.{d}.{d}.{d}:{d};branch={s}\r\n", .{ pbx_addr.ip4.bytes[0], pbx_addr.ip4.bytes[1], pbx_addr.ip4.bytes[2], pbx_addr.ip4.bytes[3], pbx_addr.ip4.port, invite_branch }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} CANCEL\r\n", .{req.cseq_num}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Content-Length: 0\r\n\r\n", .{}) catch return error.BufferTooSmall).len;

    return buf[0..offset];
}

pub fn handleResponse(
    resp: msg.Response,
    caller_addr: std.Io.net.IpAddress,
    callee_addr: std.Io.net.IpAddress,
    socket: *transport.UdpSocket,
    buf: []u8,
    rtp_sessions: *rtp.Sessions,
    allocator: std.mem.Allocator,
    fwd_buf: []u8,
) !void {
    if (resp.status_code >= 200 and resp.status_code < 300 and resp.cseq_method == .INVITE) {
        if (rtp_sessions.getSession(resp.call_id)) |session| {
            if (resp.body.len > 0) {
                const callee_sdp = try sdp.parseSdp(resp.body);
                session.callee_ip = callee_addr;
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

/// Forwards an INVITE to the given contact and returns the generated branch.
pub fn handleInvite(
    req: msg.Request,
    from_addr: std.Io.net.IpAddress,
    contact: reg.Contact,
    socket: *transport.UdpSocket,
    pbx_addr: std.Io.net.IpAddress,
    resp_buf: []u8,
    fwd_buf: []u8,
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { branch: []u8, forwarded: []u8 } {
    try sendResponse(socket, from_addr, resp_buf, 100, "Trying", req);
    const branch = try generateBranch(allocator, io);

    const forwarded = try buildForwardedRequest(req, pbx_addr, branch, fwd_buf);
    try socket.sendTo(forwarded, contact.address);
    return .{ .branch = branch, .forwarded = forwarded };
}

/// Registers (or unregisters) the sender using the To header as the AOR.
pub fn handleRegister(
    req: msg.Request,
    from_addr: std.Io.net.IpAddress,
    registrar: *reg.Registrar,
    socket: *transport.UdpSocket,
    resp_buf: []u8,
) !void {
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

/// Extracts the URI from a header value, stripping surrounding angle brackets.
pub fn extractUri(header: []const u8) []const u8 {
    if (std.mem.find(u8, header, "<")) |start| {
        const end = std.mem.find(u8, header[start..], ">") orelse return header;
        return header[start + 1 .. start + end];
    }
    return header;
}

pub fn buildResponse(
    buf: []u8,
    status: u16,
    reason: []const u8,
    req: msg.Request,
    branch: ?[]const u8,
) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "SIP/2.0 {d} {s}\r\n", .{ status, reason }) catch return error.BufferTooSmall).len;

    // Build Via header with branch
    if (branch) |b| {
        offset += (std.fmt.bufPrint(buf[offset..], "Via: {s};branch={s}\r\n", .{ req.via, b }) catch return error.BufferTooSmall).len;
    } else {
        offset += (std.fmt.bufPrint(buf[offset..], "Via: {s}\r\n", .{req.via}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall).len;

    if (req.contact) |c| {
        offset += (std.fmt.bufPrint(buf[offset..], "Contact: {s}\r\n", .{c}) catch return error.BufferTooSmall).len;
    }

    offset += (std.fmt.bufPrint(buf[offset..], "Content-Length: 0\r\n\r\n", .{}) catch return error.BufferTooSmall).len;

    return buf[0..offset];
}

pub fn sendResponse(
    socket: *transport.UdpSocket,
    to: std.Io.net.IpAddress,
    buf: []u8,
    status: u16,
    reason: []const u8,
    req: msg.Request,
) !void {
    sendResponseWithBranch(socket, to, buf, status, reason, req, null) catch |err| return err;
}

pub fn sendResponseWithBranch(
    socket: *transport.UdpSocket,
    to: std.Io.net.IpAddress,
    buf: []u8,
    status: u16,
    reason: []const u8,
    req: msg.Request,
    branch: ?[]const u8,
) !void {
    const response = std.fmt.bufPrint(buf, "SIP/2.0 {d} {s}\r\n", .{ status, reason }) catch return error.BufferTooSmall;

    const via_start = response.len;
    var via_line_len: usize = 0;

    // If we have a branch, add it to the Via header (RFC 3261 compliance)
    if (branch) |b| {
        via_line_len = (std.fmt.bufPrint(buf[via_start..], "Via: {s};branch={s}\r\n", .{ req.via, b }) catch return error.BufferTooSmall).len;
    } else {
        via_line_len = (std.fmt.bufPrint(buf[via_start..], "Via: {s}\r\n", .{req.via}) catch return error.BufferTooSmall).len;
    }

    const from_start = via_start + via_line_len;
    const from_line = std.fmt.bufPrint(buf[from_start..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall;

    const to_start = from_start + from_line.len;
    const to_line = std.fmt.bufPrint(buf[to_start..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall;
    const call_start = to_start + to_line.len;
    const call_line = std.fmt.bufPrint(buf[call_start..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall;

    const cseq_start = call_start + call_line.len;
    const cseq_line = std.fmt.bufPrint(buf[cseq_start..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall;

    const contact_start = cseq_start + cseq_line.len;
    var content_start = contact_start;
    if (req.contact) |c| {
        const contact_line = std.fmt.bufPrint(buf[contact_start..], "Contact: {s}\r\n", .{c}) catch return error.BufferTooSmall;
        content_start = contact_start + contact_line.len;
    }

    const content_len_line = std.fmt.bufPrint(buf[content_start..], "Content-Length: 0\r\n\r\n", .{}) catch return error.BufferTooSmall;

    const total_len = content_start + content_len_line.len;
    try socket.sendTo(buf[0..total_len], to);
}

/// Generates a random RFC 3261-style branch identifier.
pub fn generateBranch(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var buf: [8]u8 = undefined;
    std.Io.random(io, &buf);
    const suffix = std.mem.readInt(u64, &buf, .little);
    return std.fmt.allocPrint(allocator, "z9hG4bK{x}", .{suffix});
}

fn buildForwardedRequest(
    req: msg.Request,
    pbx_addr: std.Io.net.IpAddress,
    branch: []const u8,
    buf: []u8,
) ![]u8 {
    var offset: usize = 0;
    offset += (std.fmt.bufPrint(buf[offset..], "{s} {s} SIP/2.0\r\n", .{ req.method.toSlice(), req.request_uri }) catch return error.BufferTooSmall).len;

    const via_proto = "SIP/2.0/UDP";
    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s} {d}.{d}.{d}.{d}:{d};branch={s}\r\n", .{ via_proto, pbx_addr.ip4.bytes[0], pbx_addr.ip4.bytes[1], pbx_addr.ip4.bytes[2], pbx_addr.ip4.bytes[3], pbx_addr.ip4.port, branch }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s}\r\n", .{req.via}) catch return error.BufferTooSmall).len;
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

    offset += (std.fmt.bufPrint(buf[offset..], "Content-Length: {d}\r\n", .{req.body.len}) catch return error.BufferTooSmall).len;
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

    const via_proto = "SIP/2.0/UDP";
    offset += (std.fmt.bufPrint(buf[offset..], "Via: {s} {d}.{d}.{d}.{d}:{d}\r\n", .{ via_proto, dest_addr.ip4.bytes[0], dest_addr.ip4.bytes[1], dest_addr.ip4.bytes[2], dest_addr.ip4.bytes[3], dest_addr.ip4.port }) catch return error.BufferTooSmall).len;

    offset += (std.fmt.bufPrint(buf[offset..], "From: {s}\r\n", .{req.from}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "To: {s}\r\n", .{req.to}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Call-ID: {s}\r\n", .{req.call_id}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() }) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, MESSAGE\r\n", .{}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "Content-Length: 0\r\n", .{}) catch return error.BufferTooSmall).len;
    offset += (std.fmt.bufPrint(buf[offset..], "\r\n", .{}) catch return error.BufferTooSmall).len;
    return buf[0..offset];
}

fn buildResponseWithSdp(
    resp: msg.Response,
    buf: []u8,
    sdp_body: []const u8,
    include_via: bool,
) ![]u8 {
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
    offset += (std.fmt.bufPrint(buf[offset..], "Content-Length: {d}\r\n", .{sdp_body.len}) catch return error.BufferTooSmall).len;
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
