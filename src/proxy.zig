//! SIP request/response handling and message building for proxying.

const std = @import("std");

const auth = @import("auth.zig");
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
    const via_start = std.mem.find(u8, raw, "Via: ") orelse {
        @memcpy(out[0..raw.len], raw);
        return out[0..raw.len];
    };
    const line_end = std.mem.findPos(u8, raw, via_start, "\r\n") orelse {
        @memcpy(out[0..raw.len], raw);
        return out[0..raw.len];
    };

    // A Via line may fold several values ("Via: A, B", RFC 3261).
    // Folded: drop only the first value, keeping the "Via: " prefix.
    // Single: drop the whole line (original behavior).
    const prefix_end = via_start + "Via: ".len;
    var keep_end = via_start;
    var drop_end = line_end + 2;
    if (std.mem.findPos(u8, raw, prefix_end, ",")) |comma| {
        if (comma < line_end) {
            keep_end = prefix_end;
            drop_end = comma + 1;
            if (drop_end < raw.len and raw[drop_end] == ' ') drop_end += 1;
        }
    }

    const tail = raw[drop_end..];
    @memcpy(out[0..keep_end], raw[0..keep_end]);
    @memcpy(out[keep_end..][0..tail.len], tail);
    return out[0 .. raw.len - (drop_end - keep_end)];
}

/// Print into a fixed-buffer writer, mapping overflow to BufferTooSmall.
fn emit(w: *std.Io.Writer, comptime format: []const u8, args: anytype) error{BufferTooSmall}!void {
    w.print(format, args) catch return error.BufferTooSmall;
}

fn buildCancelRequest(
    req: msg.Request,
    pbx_addr: std.Io.net.IpAddress,
    invite_branch: []const u8,
    buf: []u8,
) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "CANCEL {s} SIP/2.0\r\n", .{req.request_uri});
    try emit(&w, "Via: SIP/2.0/UDP {d}.{d}.{d}.{d}:{d};branch={s}\r\n", .{ pbx_addr.ip4.bytes[0], pbx_addr.ip4.bytes[1], pbx_addr.ip4.bytes[2], pbx_addr.ip4.bytes[3], pbx_addr.ip4.port, invite_branch });

    try emit(&w, "From: {s}\r\n", .{req.from});
    try emit(&w, "To: {s}\r\n", .{req.to});
    try emit(&w, "Call-ID: {s}\r\n", .{req.call_id});
    try emit(&w, "CSeq: {d} CANCEL\r\n", .{req.cseq_num});
    try emit(&w, "Content-Length: 0\r\n\r\n", .{});
    return w.buffered();
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
                rtp_sessions.setCallee(resp.call_id, callee_addr, callee_sdp.port, callee_sdp.payload_type);

                const rewritten_sdp = try sdp.rewriteSdp(resp.body, "127.0.0.1", session.relay_caller_port, allocator);
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
    authenticator: *auth.Auth,
    socket: *transport.UdpSocket,
    resp_buf: []u8,
    allocator: std.mem.Allocator,
) !void {
    const username = authenticator.verifyRequest(req) catch |err| {
        // Authentication failures are answers, not errors: challenge the
        // client (stale nonces say so explicitly per RFC 3261).
        const stale = err == error.StaleNonce;
        if (stale) log.info("stale nonce for {s}, re-challenging", .{req.request_uri});
        return try sendUnauthorized(socket, from_addr, authenticator, resp_buf, req, allocator, stale);
    };

    log.debug("REGISTER {s} authenticated as {s}", .{ req.request_uri, username });
    const aor = extractUri(req.to);
    if (req.expires) |exp| {
        if (exp == 0) {
            registrar.unregister(aor);
            return try sendResponse(socket, from_addr, resp_buf, 200, "OK", req);
        }
    }

    const expires = req.expires orelse 3600;
    registrar.register(aor, from_addr, expires, req.call_id, req.cseq_num) catch |err| switch (err) {
        // A stale or duplicated REGISTER retransmission is not an error: reply
        // 200 OK per RFC 3261
        error.DuplicateCallId => {},
        else => return err,
    };
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
    www_authenticate: ?[]const u8,
) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "SIP/2.0 {d} {s}\r\n", .{ status, reason });
    // A generated response echoes the top Via unchanged (RFC 3261);
    // appending a branch would corrupt transaction matching downstream.
    try emit(&w, "Via: {s}\r\n", .{req.via});
    try emit(&w, "From: {s}\r\n", .{req.from});
    try emit(&w, "To: {s}\r\n", .{req.to});
    try emit(&w, "Call-ID: {s}\r\n", .{req.call_id});
    try emit(&w, "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() });
    if (www_authenticate) |wa| {
        try emit(&w, "WWW-Authenticate: {s}\r\n", .{wa});
    }
    if (req.contact) |c| {
        try emit(&w, "Contact: {s}\r\n", .{c});
    }

    try emit(&w, "Content-Length: 0\r\n\r\n", .{});
    return w.buffered();
}

/// Renders a 408 Request Timeout for a timed-out outbound INVITE.
/// All header values must outlive the call; typically owned dupes.
pub fn buildTimeoutResponse(
    buf: []u8,
    call_id: []const u8,
    cseq_num: u32,
    via: []const u8,
    from: []const u8,
    to: []const u8,
) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "SIP/2.0 408 Request Timeout\r\n", .{});
    try emit(&w, "Via: {s}\r\n", .{via});
    try emit(&w, "From: {s}\r\n", .{from});
    try emit(&w, "To: {s}\r\n", .{to});
    try emit(&w, "Call-ID: {s}\r\n", .{call_id});
    try emit(&w, "CSeq: {d} INVITE\r\n", .{cseq_num});
    try emit(&w, "Content-Length: 0\r\n\r\n", .{});
    return w.buffered();
}

pub fn sendResponse(
    socket: *transport.UdpSocket,
    to: std.Io.net.IpAddress,
    buf: []u8,
    status: u16,
    reason: []const u8,
    req: msg.Request,
) !void {
    sendResponseWithBranch(socket, to, buf, status, reason, req) catch |err| return err;
}

pub fn sendResponseWithBranch(
    socket: *transport.UdpSocket,
    to: std.Io.net.IpAddress,
    buf: []u8,
    status: u16,
    reason: []const u8,
    req: msg.Request,
) !void {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "SIP/2.0 {d} {s}\r\n", .{ status, reason });
    // Echo the top Via unchanged; see buildResponse.
    try emit(&w, "Via: {s}\r\n", .{req.via});

    try emit(&w, "From: {s}\r\n", .{req.from});
    try emit(&w, "To: {s}\r\n", .{req.to});
    try emit(&w, "Call-ID: {s}\r\n", .{req.call_id});
    try emit(&w, "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() });
    if (req.contact) |c| {
        try emit(&w, "Contact: {s}\r\n", .{c});
    }

    try emit(&w, "Content-Length: 0\r\n\r\n", .{});
    try socket.sendTo(w.buffered(), to);
}

/// Answers 401 with a fresh nonce challenge.
fn sendUnauthorized(
    socket: *transport.UdpSocket,
    to: std.Io.net.IpAddress,
    authenticator: *auth.Auth,
    buf: []u8,
    req: msg.Request,
    allocator: std.mem.Allocator,
    stale: bool,
) !void {
    const nonce = try authenticator.issueNonce();
    const www_auth = try auth.challenge(allocator, nonce[0..], stale);
    defer allocator.free(www_auth);
    const response = try buildResponse(buf, 401, "Unauthorized", req, www_auth);
    try socket.sendTo(response, to);
}

/// Generates a random RFC 3261-style branch identifier.
pub fn generateBranch(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var buf: [8]u8 = undefined;
    std.Io.random(io, &buf);
    const suffix = std.mem.readInt(u64, &buf, .little);
    return allocator.print("z9hG4bK{x}", .{suffix});
}

fn buildForwardedRequest(
    req: msg.Request,
    pbx_addr: std.Io.net.IpAddress,
    branch: []const u8,
    buf: []u8,
) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "{s} {s} SIP/2.0\r\n", .{ req.method.toSlice(), req.request_uri });

    const via_proto = "SIP/2.0/UDP";
    try emit(&w, "Via: {s} {d}.{d}.{d}.{d}:{d};branch={s}\r\n", .{ via_proto, pbx_addr.ip4.bytes[0], pbx_addr.ip4.bytes[1], pbx_addr.ip4.bytes[2], pbx_addr.ip4.bytes[3], pbx_addr.ip4.port, branch });

    try emit(&w, "Via: {s}\r\n", .{req.via});
    const max_forwards = req.max_forwards orelse 70;
    if (max_forwards == 0) return error.MaxForwardsExceeded;

    try emit(&w, "Max-Forwards: {d}\r\n", .{max_forwards - 1});
    try emit(&w, "From: {s}\r\n", .{req.from});
    try emit(&w, "To: {s}\r\n", .{req.to});
    try emit(&w, "Call-ID: {s}\r\n", .{req.call_id});
    try emit(&w, "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() });
    if (req.contact) |c| {
        try emit(&w, "Contact: {s}\r\n", .{c});
    }
    if (req.content_type) |ct| {
        try emit(&w, "Content-Type: {s}\r\n", .{ct});
    }

    try emit(&w, "Content-Length: {d}\r\n", .{req.body.len});
    try emit(&w, "\r\n", .{});
    if (req.body.len > 0) {
        w.writeAll(req.body) catch return error.BufferTooSmall;
    }
    return w.buffered();
}

fn buildOptionsRequest(req: msg.Request, dest_addr: std.Io.net.IpAddress, buf: []u8) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "OPTIONS {s} SIP/2.0\r\n", .{req.request_uri});

    const via_proto = "SIP/2.0/UDP";
    try emit(&w, "Via: {s} {d}.{d}.{d}.{d}:{d}\r\n", .{ via_proto, dest_addr.ip4.bytes[0], dest_addr.ip4.bytes[1], dest_addr.ip4.bytes[2], dest_addr.ip4.bytes[3], dest_addr.ip4.port });

    try emit(&w, "From: {s}\r\n", .{req.from});
    try emit(&w, "To: {s}\r\n", .{req.to});
    try emit(&w, "Call-ID: {s}\r\n", .{req.call_id});
    try emit(&w, "CSeq: {d} {s}\r\n", .{ req.cseq_num, req.cseq_method.toSlice() });
    try emit(&w, "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, MESSAGE\r\n", .{});
    try emit(&w, "Content-Length: 0\r\n", .{});
    try emit(&w, "\r\n", .{});
    return w.buffered();
}

fn buildResponseWithSdp(
    resp: msg.Response,
    buf: []u8,
    sdp_body: []const u8,
    include_via: bool,
) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try emit(&w, "SIP/2.0 {d} {s}\r\n", .{ resp.status_code, resp.reason_phrase });
    if (include_via) {
        try emit(&w, "Via: {s}\r\n", .{resp.via});
    }

    try emit(&w, "From: {s}\r\n", .{resp.from});
    try emit(&w, "To: {s}", .{resp.to});
    if (resp.to_tag) |tag| {
        try emit(&w, ";tag={s}", .{tag});
    }

    try emit(&w, "\r\n", .{});
    try emit(&w, "Call-ID: {s}\r\n", .{resp.call_id});
    try emit(&w, "CSeq: {d} {s}\r\n", .{ resp.cseq_num, resp.cseq_method.toSlice() });
    if (resp.contact) |c| {
        try emit(&w, "Contact: {s}\r\n", .{c});
    }

    try emit(&w, "Content-Type: application/sdp\r\n", .{});
    try emit(&w, "Content-Length: {d}\r\n", .{sdp_body.len});
    try emit(&w, "\r\n", .{});
    if (sdp_body.len > 0) {
        w.writeAll(sdp_body) catch return error.BufferTooSmall;
    }
    return w.buffered();
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

test "buildTimeoutResponse renders 408" {
    var buf: [1024]u8 = undefined;
    const out = try buildTimeoutResponse(
        &buf,
        "call-1",
        1,
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
        "<sip:alice@127.0.0.1:5060>;tag=aliceTag",
        "<sip:bob@127.0.0.1:5060>",
    );
    try std.testing.expectEqualStrings(
        "SIP/2.0 408 Request Timeout\r\n" ++
            "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc\r\n" ++
            "From: <sip:alice@127.0.0.1:5060>;tag=aliceTag\r\n" ++
            "To: <sip:bob@127.0.0.1:5060>\r\n" ++
            "Call-ID: call-1\r\n" ++
            "CSeq: 1 INVITE\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n",
        out,
    );
}

fn mfTestRequest(max_forwards: ?u32) msg.Request {
    return .{
        .method = .INVITE,
        .request_uri = "sip:bob@127.0.0.1:5060",
        .via = "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKorig",
        .via_branch = "z9hG4bKorig",
        .via_branch2 = "",
        .from = "<sip:alice@127.0.0.1:5060>;tag=aliceTag",
        .from_tag = "aliceTag",
        .to = "<sip:bob@127.0.0.1:5060>",
        .to_tag = null,
        .call_id = "mf-test@127.0.0.1",
        .cseq_num = 1,
        .cseq_method = .INVITE,
        .contact = null,
        .expires = null,
        .content_type = null,
        .max_forwards = max_forwards,
        .authorization = null,
        .body = "",
    };
}

const mfTestPbxAddr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 5060 } };

test "buildForwardedRequest decrements Max-Forwards" {
    var buf: [2048]u8 = undefined;
    const out = try buildForwardedRequest(mfTestRequest(5), mfTestPbxAddr, "z9hG4bKfwd", &buf);
    try std.testing.expect(std.mem.find(u8, out, "Max-Forwards: 4\r\n") != null);
}

test "buildForwardedRequest defaults absent Max-Forwards to 69" {
    var buf: [2048]u8 = undefined;
    const out = try buildForwardedRequest(mfTestRequest(null), mfTestPbxAddr, "z9hG4bKfwd", &buf);
    try std.testing.expect(std.mem.find(u8, out, "Max-Forwards: 69\r\n") != null);
}

test "buildForwardedRequest rejects exhausted Max-Forwards" {
    var buf: [2048]u8 = undefined;
    const out = buildForwardedRequest(mfTestRequest(0), mfTestPbxAddr, "z9hG4bKfwd", &buf);
    try std.testing.expectError(error.MaxForwardsExceeded, out);
}

test "buildResponse emits WWW-Authenticate when given" {
    var buf: [1024]u8 = undefined;
    const out = try buildResponse(&buf, 401, "Unauthorized", mfTestRequest(70), "Digest realm=\"pbx\", nonce=\"abc\", algorithm=MD5");
    try std.testing.expect(std.mem.find(u8, out, "SIP/2.0 401 Unauthorized\r\n") != null);
    try std.testing.expect(std.mem.find(u8, out, "WWW-Authenticate: Digest realm=\"pbx\", nonce=\"abc\", algorithm=MD5\r\n") != null);
}

test "buildResponse omits WWW-Authenticate when null" {
    var buf: [1024]u8 = undefined;
    const out = try buildResponse(&buf, 404, "Not Found", mfTestRequest(70), null);
    try std.testing.expect(std.mem.find(u8, out, "WWW-Authenticate:") == null);
}

test "stripTopVia removes only the first value of a folded Via" {
    var out: [512]u8 = undefined;
    const raw =
        "SIP/2.0 180 Ringing\r\n" ++
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKtop, SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKnext\r\n" ++
        "From: a\r\n" ++
        "\r\n";
    const stripped = stripTopVia(raw, &out);
    try std.testing.expectEqualStrings(
        "SIP/2.0 180 Ringing\r\n" ++
            "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKnext\r\n" ++
            "From: a\r\n" ++
            "\r\n",
        stripped,
    );
}

test "stripTopVia removes a lone Via line whole" {
    var out: [512]u8 = undefined;
    const raw =
        "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKonly\r\n" ++
        "From: a\r\n" ++
        "\r\n";
    const stripped = stripTopVia(raw, &out);
    try std.testing.expectEqualStrings(
        "SIP/2.0 200 OK\r\n" ++
            "From: a\r\n" ++
            "\r\n",
        stripped,
    );
}
