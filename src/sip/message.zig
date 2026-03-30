const std = @import("std");

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

pub const Message = union(enum) {
    request: Request,
    response: Response,
};

pub const ParseError = error{
    MalformedStartLine,
    MissingMandatoryHeader,
    InvalidCSeq,
    UnknownMethod,
    InvalidContentLength,
    BodyTooShort,
};

pub const RegistrarError = error{
    UserNotFound,
    RegistrationExpired,
    DuplicateCallId,
};

pub const TransportError = error{
    SocketBindFailed,
    SendFailed,
    PacketTooLarge,
};
