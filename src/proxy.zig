const std = @import("std");
const msg = @import("sip/message.zig");
const reg = @import("registrar.zig");
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

pub fn handleAck(req: msg.Request, dest_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, buf: []u8) !void {
    _ = registrar;
    _ = req;
    try socket.sendTo(buf, dest_addr);
}

pub fn handleBye(req: msg.Request, dest_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, buf: []u8) !void {
    _ = registrar;
    _ = req;
    try socket.sendTo(buf, dest_addr);
}

pub fn handleCancel(req: msg.Request, caller_addr: std.Io.net.IpAddress, registrar: *reg.Registrar, socket: *transport.UdpSocket, resp_buf: []u8, fwd_buf: []u8) !void {
    try sendResponse(socket, caller_addr, resp_buf, 200, "OK", req);

    const dest_aor = extractUri(req.request_uri);
    const contact = registrar.lookup(dest_aor);
    if (contact) |c| {
        const forwarded = try buildCancelRequest(req, c.address, fwd_buf);
        try socket.sendTo(forwarded, c.address);
    }
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

pub fn handleResponse(resp: msg.Response, caller_addr: std.Io.net.IpAddress, socket: *transport.UdpSocket, buf: []u8) !void {
    _ = resp;
    try socket.sendTo(buf, caller_addr);
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

fn extractUri(header: []const u8) []const u8 {
    if (std.mem.indexOf(u8, header, "<")) |start| {
        const end = std.mem.indexOf(u8, header[start..], ">") orelse return header;
        return header[start + 1 .. start + end];
    }
    return header;
}

fn sendResponse(socket: *transport.UdpSocket, to: std.Io.net.IpAddress, buf: []u8, status: u16, reason: []const u8, req: msg.Request) !void {
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

fn generateBranch(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
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
    offset += (std.fmt.bufPrint(buf[offset..], "SIP/2.0 200 OK\r\n", .{}) catch return error.BufferTooSmall).len;

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
