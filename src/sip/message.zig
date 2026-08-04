//! SIP message model: method, request/response headers, and the parsed message union.

const std = @import("std");

const log = std.log.scoped(.message);

/// SIP request methods supported by the PBX.
pub const Method = enum {
    REGISTER,
    INVITE,
    ACK,
    BYE,
    CANCEL,
    OPTIONS,
    MESSAGE,

    pub fn fromSlice(s: []const u8) !Method {
        if (std.mem.eql(u8, s, "REGISTER")) return .REGISTER;
        if (std.mem.eql(u8, s, "INVITE")) return .INVITE;
        if (std.mem.eql(u8, s, "ACK")) return .ACK;
        if (std.mem.eql(u8, s, "BYE")) return .BYE;
        if (std.mem.eql(u8, s, "CANCEL")) return .CANCEL;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, s, "MESSAGE")) return .MESSAGE;
        return error.UnknownMethod;
    }

    pub fn toSlice(self: Method) []const u8 {
        return @tagName(self);
    }
};

/// Broad status-class bucket derived from a response code.
pub const ResponseClass = enum {
    provisional,
    success,
    redirect,
    client_error,
    server_error,
    global_error,

    pub fn of(code: u16) ResponseClass {
        return switch (code / 100) {
            1 => .provisional,
            2 => .success,
            3 => .redirect,
            4 => .client_error,
            5 => .server_error,
            else => .global_error,
        };
    }
};

/// Parsed SIP request headers.
pub const Request = struct {
    method: Method,
    request_uri: []const u8,
    via: []const u8,
    via_branch: []const u8,
    from: []const u8,
    from_tag: []const u8,
    to: []const u8,
    to_tag: ?[]const u8,
    call_id: []const u8,
    cseq_num: u32,
    cseq_method: Method,
    contact: ?[]const u8,
    expires: ?u32,
    content_type: ?[]const u8,
    max_forwards: ?u32,
    body: []const u8,
};

/// Parsed SIP response headers.
pub const Response = struct {
    status_code: u16,
    reason_phrase: []const u8,
    via: []const u8,
    via_branch: []const u8,
    from: []const u8,
    from_tag: []const u8,
    to: []const u8,
    to_tag: ?[]const u8,
    call_id: []const u8,
    cseq_num: u32,
    cseq_method: Method,
    contact: ?[]const u8,
    body: []const u8,
};

/// A parsed SIP message: either a request or a response.
pub const Message = union(enum) {
    request: Request,
    response: Response,
};

test "ResponseClass.of buckets every status code" {
    try std.testing.expectEqual(ResponseClass.provisional, ResponseClass.of(100));
    try std.testing.expectEqual(ResponseClass.provisional, ResponseClass.of(180));
    try std.testing.expectEqual(ResponseClass.success, ResponseClass.of(200));
    try std.testing.expectEqual(ResponseClass.redirect, ResponseClass.of(302));
    try std.testing.expectEqual(ResponseClass.client_error, ResponseClass.of(404));
    try std.testing.expectEqual(ResponseClass.client_error, ResponseClass.of(487));
    try std.testing.expectEqual(ResponseClass.server_error, ResponseClass.of(500));
    try std.testing.expectEqual(ResponseClass.global_error, ResponseClass.of(600));
}
