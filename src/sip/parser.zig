//! Textual SIP message parsing into the message model.

const std = @import("std");

const msg = @import("message.zig");

const log = std.log.scoped(.parser);

pub fn parse(buf: []const u8) !msg.Message {
    const sep = std.mem.find(u8, buf, "\r\n\r\n") orelse return error.MalformedStartLine;
    const header_section = buf[0..sep];
    const body = if (sep + 4 < buf.len) buf[sep + 4 ..] else "";

    var lines = std.mem.splitSequence(u8, header_section, "\r\n");
    const start_line = lines.next() orelse return error.MalformedStartLine;
    if (std.mem.startsWith(u8, start_line, "SIP/")) {
        const resp = try parseResponse(start_line, &lines, body);
        return .{ .response = resp };
    } else {
        const req = try parseRequest(start_line, &lines, body);
        return .{ .request = req };
    }
}

fn parseRequest(
    start: []const u8,
    lines: *std.mem.SplitIterator(u8, .sequence),
    body: []const u8,
) !msg.Request {
    var tokens = std.mem.splitScalar(u8, start, ' ');
    const method_str = tokens.next() orelse return error.MalformedStartLine;
    const uri = tokens.next() orelse return error.MalformedStartLine;
    const version = tokens.next() orelse return error.MalformedStartLine;
    if (!std.mem.eql(u8, version, "SIP/2.0")) {
        return error.MalformedStartLine;
    }

    var req = msg.Request{
        .method = try msg.Method.fromSlice(method_str),
        .request_uri = uri,
        .via = "",
        .via_branch = "",
        .via_branch2 = "",
        .from = "",
        .from_tag = "",
        .to = "",
        .to_tag = null,
        .call_id = "",
        .cseq_num = 0,
        .cseq_method = .REGISTER,
        .contact = null,
        .expires = null,
        .content_type = null,
        .max_forwards = null,
        .authorization = null,
        .body = body,
    };

    try parseRequestHeaders(&req, lines);
    return req;
}

fn parseResponse(
    start: []const u8,
    lines: *std.mem.SplitIterator(u8, .sequence),
    body: []const u8,
) !msg.Response {
    var tokens = std.mem.splitScalar(u8, start, ' ');
    const version = tokens.next() orelse return error.MalformedStartLine;
    const status_str = tokens.next() orelse return error.MalformedStartLine;
    if (!std.mem.eql(u8, version, "SIP/2.0")) {
        return error.MalformedStartLine;
    }

    const status_code = std.fmt.parseInt(u16, status_str, 10) catch return error.MalformedStartLine;
    const reason_start = status_str.len + 1 + version.len + 1;
    const reason_end = std.mem.find(u8, start, "\r\n") orelse start.len;
    const reason = std.mem.trim(u8, start[reason_start..reason_end], " ");
    var resp = msg.Response{
        .status_code = status_code,
        .reason_phrase = reason,
        .via = "",
        .via_branch = "",
        .via_branch2 = "",
        .from = "",
        .from_tag = "",
        .to = "",
        .to_tag = null,
        .call_id = "",
        .cseq_num = 0,
        .cseq_method = .REGISTER,
        .contact = null,
        .body = body,
    };

    try parseResponseHeaders(&resp, lines);
    return resp;
}

fn parseRequestHeaders(out: *msg.Request, lines: *std.mem.SplitIterator(u8, .sequence)) !void {
    while (lines.next()) |line| {
        if (line.len == 0) break;

        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");

        var key_lower_buf: [64]u8 = undefined;
        const key_lower = std.ascii.lowerString(&key_lower_buf, key);
        if (std.mem.eql(u8, key_lower, "via") or std.mem.eql(u8, key_lower, "v")) {
            if (out.via.len == 0) {
                out.via = value;
                out.via_branch = firstBranch(value);
                out.via_branch2 = secondBranch(value);
            } else if (out.via_branch2.len == 0) {
                out.via_branch2 = firstBranch(value);
            }
        } else if (std.mem.eql(u8, key_lower, "from") or std.mem.eql(u8, key_lower, "f")) {
            out.from = value;
            out.from_tag = extractParam(value, "tag") orelse "";
        } else if (std.mem.eql(u8, key_lower, "to") or std.mem.eql(u8, key_lower, "t")) {
            out.to = value;
            out.to_tag = extractParam(value, "tag");
        } else if (std.mem.eql(u8, key_lower, "call-id") or std.mem.eql(u8, key_lower, "i")) {
            out.call_id = value;
        } else if (std.mem.eql(u8, key_lower, "cseq")) {
            try parseCSeq(out, value);
        } else if (std.mem.eql(u8, key_lower, "contact") or std.mem.eql(u8, key_lower, "m")) {
            out.contact = value;
        } else if (std.mem.eql(u8, key_lower, "expires")) {
            out.expires = std.fmt.parseInt(u32, value, 10) catch null;
        } else if (std.mem.eql(u8, key_lower, "content-type") or std.mem.eql(u8, key_lower, "c")) {
            out.content_type = value;
        } else if (std.mem.eql(u8, key_lower, "max-forwards")) {
            out.max_forwards = std.fmt.parseInt(u32, value, 10) catch null;
        } else if (std.mem.eql(u8, key_lower, "authorization")) {
            out.authorization = value;
        }
    }
}

fn parseResponseHeaders(out: *msg.Response, lines: *std.mem.SplitIterator(u8, .sequence)) !void {
    while (lines.next()) |line| {
        if (line.len == 0) break;

        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");

        var key_lower_buf: [64]u8 = undefined;
        const key_lower = std.ascii.lowerString(&key_lower_buf, key);
        if (std.mem.eql(u8, key_lower, "via") or std.mem.eql(u8, key_lower, "v")) {
            if (out.via.len == 0) {
                out.via = value;
                out.via_branch = firstBranch(value);
                out.via_branch2 = secondBranch(value);
            } else if (out.via_branch2.len == 0) {
                out.via_branch2 = firstBranch(value);
            }
        } else if (std.mem.eql(u8, key_lower, "from") or std.mem.eql(u8, key_lower, "f")) {
            out.from = value;
            out.from_tag = extractParam(value, "tag") orelse "";
        } else if (std.mem.eql(u8, key_lower, "to") or std.mem.eql(u8, key_lower, "t")) {
            out.to = value;
            out.to_tag = extractParam(value, "tag");
        } else if (std.mem.eql(u8, key_lower, "call-id") or std.mem.eql(u8, key_lower, "i")) {
            out.call_id = value;
        } else if (std.mem.eql(u8, key_lower, "cseq")) {
            try parseCSeq(out, value);
        } else if (std.mem.eql(u8, key_lower, "contact") or std.mem.eql(u8, key_lower, "m")) {
            out.contact = value;
        }
    }
}

fn extractParam(value: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, value, ';');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        const eq = std.mem.findScalar(u8, trimmed, '=') orelse continue;
        if (std.mem.eql(u8, trimmed[0..eq], name)) {
            return trimmed[eq + 1 ..];
        }
    }
    return null;
}

/// Branch of the first Via value in a (possibly folded) Via line.
/// A folded line ("Via: A, B") carries one branch per value; the first
/// belongs to this (top) Via. Via params never contain commas, so splitting
/// on the first comma is safe.
fn firstBranch(value: []const u8) []const u8 {
    var vals = std.mem.splitScalar(u8, value, ',');
    const first = std.mem.trim(u8, vals.next() orelse return "", " ");
    return extractParam(first, "branch") orelse "";
}

/// Branch of the second Via value in a folded Via line, or "".
fn secondBranch(value: []const u8) []const u8 {
    var vals = std.mem.splitScalar(u8, value, ',');
    _ = vals.next();

    const second = std.mem.trim(u8, vals.next() orelse return "", " ");
    return extractParam(second, "branch") orelse "";
}

fn parseCSeq(out: anytype, value: []const u8) !void {
    var tokens = std.mem.splitScalar(u8, value, ' ');
    const num_str = tokens.next() orelse return error.InvalidCSeq;
    const method_str = tokens.next() orelse return error.InvalidCSeq;

    out.cseq_num = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidCSeq;
    out.cseq_method = try msg.Method.fromSlice(method_str);
}

test "parse REGISTER request" {
    const raw =
        "REGISTER sip:pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKabc\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=xyz\r\n" ++
        "To: Alice <sip:alice@pbx.local>\r\n" ++
        "Call-ID: abc123@192.168.1.5\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:alice@192.168.1.5:5060>\r\n" ++
        "Expires: 3600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.REGISTER, req.method);
    try std.testing.expectEqualStrings("sip:pbx.local", req.request_uri);
    try std.testing.expectEqualStrings("z9hG4bKabc", req.via_branch);
    try std.testing.expectEqualStrings("xyz", req.from_tag);
    try std.testing.expectEqual(@as(u32, 1), req.cseq_num);
    try std.testing.expectEqual(@as(?u32, 3600), req.expires);
}

test "parse INVITE request" {
    const raw =
        "INVITE sip:bob@pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKdef\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: call456@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@192.168.1.5:5060>\r\n" ++
        "Content-Type: application/sdp\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.INVITE, req.method);
    try std.testing.expectEqualStrings("sip:bob@pbx.local", req.request_uri);
    try std.testing.expectEqualStrings("z9hG4bKdef", req.via_branch);
    try std.testing.expectEqualStrings("aaa", req.from_tag);
}

test "parse 200 OK response" {
    const raw =
        "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKabc\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=xyz\r\n" ++
        "To: Alice <sip:alice@pbx.local>;tag=bbb\r\n" ++
        "Call-ID: abc123@192.168.1.5\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Contact: <sip:alice@192.168.1.5:5060>\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("OK", resp.reason_phrase);
    try std.testing.expectEqual(@as(u32, 1), resp.cseq_num);
}

test "parse MESSAGE request (RFC 3428)" {
    const raw =
        "MESSAGE sip:user2@domain.com SIP/2.0\r\n" ++
        "Via: SIP/2.0/TCP user1pc.domain.com;branch=z9hG4bK776sgdkse\r\n" ++
        "Max-Forwards: 70\r\n" ++
        "From: sip:user1@domain.com;tag=49583\r\n" ++
        "To: sip:user2@domain.com\r\n" ++
        "Call-ID: asd88asd77a@1.2.3.4\r\n" ++
        "CSeq: 1 MESSAGE\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 18\r\n" ++
        "\r\n" ++
        "Watson, come here.";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.MESSAGE, req.method);
    try std.testing.expectEqualStrings("sip:user2@domain.com", req.request_uri);
    try std.testing.expectEqualStrings("Watson, come here.", req.body);
    try std.testing.expectEqual(@as(?u32, 70), req.max_forwards);
}

test "parse error on malformed start line" {
    const raw = "NOT_A_SIP_MESSAGE\r\n\r\n";
    const result = parse(raw);
    try std.testing.expectError(error.MalformedStartLine, result);
}

test "parse INVITE with SDP body" {
    const raw =
        "INVITE sip:bob@pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKabc123\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=call123\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: xyz123@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Contact: <sip:alice@192.168.1.5:5060>\r\n" ++
        "Content-Type: application/sdp\r\n" ++
        "Content-Length: 82\r\n" ++
        "\r\n" ++
        "v=0\r\n" ++
        "o=alice 123456 789 IN IP4 192.168.1.5\r\n" ++
        "s=Session\r\n" ++
        "c=IN IP4 192.168.1.5\r\n" ++
        "m=audio 8000 RTP/AVP 0\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.INVITE, req.method);
    try std.testing.expectEqualStrings("sip:bob@pbx.local", req.request_uri);
    try std.testing.expectEqualStrings("z9hG4bKabc123", req.via_branch);
    try std.testing.expectEqualStrings("call123", req.from_tag);
    try std.testing.expectEqualStrings("application/sdp", req.content_type.?);
    try std.testing.expectEqualStrings("v=0\r\no=alice 123456 789 IN IP4 192.168.1.5\r\ns=Session\r\nc=IN IP4 192.168.1.5\r\nm=audio 8000 RTP/AVP 0\r\n", req.body);
}

test "parse BYE request" {
    const raw =
        "BYE sip:alice@pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKbye\r\n" ++
        "From: Bob <sip:bob@pbx.local>;tag=bbb\r\n" ++
        "To: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "Call-ID: call789@192.168.1.10\r\n" ++
        "CSeq: 2 BYE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.BYE, req.method);
    try std.testing.expectEqualStrings("sip:alice@pbx.local", req.request_uri);
    try std.testing.expectEqual(@as(u32, 2), req.cseq_num);
}

test "parse CANCEL request" {
    const raw =
        "CANCEL sip:bob@pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKcancel\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=ccc\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: call555@192.168.1.5\r\n" ++
        "CSeq: 1 CANCEL\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.CANCEL, req.method);
    try std.testing.expectEqualStrings("sip:bob@pbx.local", req.request_uri);
}

test "parse 180 Ringing response" {
    const raw =
        "SIP/2.0 180 Ringing\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKring\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=rrr\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: call111@192.168.1.10\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqual(@as(u16, 180), resp.status_code);
    try std.testing.expectEqualStrings("Ringing", resp.reason_phrase);
}

test "parse 404 Not Found response" {
    const raw =
        "SIP/2.0 404 Not Found\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKnotfound\r\n" ++
        "From: Alice <sip:alice@pbx.local>\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: call999@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqual(@as(u16, 404), resp.status_code);
    try std.testing.expectEqualStrings("Not Found", resp.reason_phrase);
}

test "parse request without Contact header" {
    const raw =
        "OPTIONS sip:pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKopts\r\n" ++
        "From: Alice <sip:alice@pbx.local>\r\n" ++
        "To: <sip:pbx.local>\r\n" ++
        "Call-ID: opts123@192.168.1.5\r\n" ++
        "CSeq: 1 OPTIONS\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(msg.Method.OPTIONS, req.method);
    try std.testing.expectEqual(null, req.contact);
}

test "parse request with Expires header" {
    const raw =
        "REGISTER sip:pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKreg\r\n" ++
        "From: Alice <sip:alice@pbx.local>\r\n" ++
        "To: Alice <sip:alice@pbx.local>\r\n" ++
        "Call-ID: reg999@192.168.1.5\r\n" ++
        "CSeq: 1 REGISTER\r\n" ++
        "Expires: 600\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqual(@as(?u32, 600), req.expires);
}

test "parse response with To tag" {
    const raw =
        "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKok\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=fromTag\r\n" ++
        "To: Bob <sip:bob@pbx.local>;tag=toTag\r\n" ++
        "Call-ID: resp123@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqualStrings("toTag", resp.to_tag.?);
}

test "extractParam exact match" {
    try std.testing.expectEqualStrings("abc", extractParam("tag=abc;tag2=xyz", "tag").?);
    try std.testing.expectEqualStrings("xyz", extractParam("tag=abc;tag2=xyz", "tag2").?);
    try std.testing.expectEqualStrings("z9hG4bK1", extractParam(";branch=z9hG4bK1;tag2=foo", "branch").?);
}

test "extractParam does not prefix-match" {
    try std.testing.expect(extractParam("tag2=xyz", "tag") == null);
    try std.testing.expect(extractParam("branchy=1", "branch") == null);
}

test "extractParam no-match and no-equals returns null" {
    try std.testing.expect(extractParam("tag=abc", "branch") == null);
    try std.testing.expect(extractParam("tagonly", "tag") == null);
}

test "parse request captures second Via branch" {
    const raw =
        "INVITE sip:bob@pbx.local SIP/2.0\r\n" ++
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfirst\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKsecond\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: via2@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const req = result.request;

    try std.testing.expectEqualStrings("z9hG4bKfirst", req.via_branch);
    try std.testing.expectEqualStrings("z9hG4bKsecond", req.via_branch2);
}

test "parse response captures second Via branch" {
    const raw =
        "SIP/2.0 486 Busy Here\r\n" ++
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpbx\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKcaller\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "To: Bob <sip:bob@pbx.local>;tag=bbb\r\n" ++
        "Call-ID: via2resp@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqualStrings("z9hG4bKpbx", resp.via_branch);
    try std.testing.expectEqualStrings("z9hG4bKcaller", resp.via_branch2);
}

test "parse single Via leaves second branch empty" {
    const raw =
        "SIP/2.0 200 OK\r\n" ++
        "Via: SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKonly\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "To: Bob <sip:bob@pbx.local>;tag=bbb\r\n" ++
        "Call-ID: singlevia@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqualStrings("z9hG4bKonly", resp.via_branch);
    try std.testing.expectEqualStrings("", resp.via_branch2);
}

test "parse folded Via line takes first branch, second value" {
    const raw =
        "SIP/2.0 180 Ringing\r\n" ++
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfold1, SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKfold2\r\n" ++
        "From: Alice <sip:alice@pbx.local>;tag=aaa\r\n" ++
        "To: Bob <sip:bob@pbx.local>\r\n" ++
        "Call-ID: folded@192.168.1.5\r\n" ++
        "CSeq: 1 INVITE\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    const result = try parse(raw);
    const resp = result.response;

    try std.testing.expectEqualStrings("z9hG4bKfold1", resp.via_branch);
    try std.testing.expectEqualStrings("z9hG4bKfold2", resp.via_branch2);
}
