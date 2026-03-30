const std = @import("std");

pub const MediaInfo = struct {
    ip_addr: []const u8,
    port: u16,
    payload_type: u7,
};

pub fn parseSdp(body: []const u8) !MediaInfo {
    var ip_addr: []const u8 = "";
    var port: u16 = 0;
    var payload_type: u7 = 0;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len < 2) continue;
        if (std.mem.startsWith(u8, line, "c=IN IP4 ")) {
            ip_addr = line[9..];
        } else if (std.mem.startsWith(u8, line, "m=audio ")) {
            var tokens = std.mem.splitScalar(u8, line[8..], ' ');
            const port_str = tokens.next() orelse return error.MalformedSdp;
            port = std.fmt.parseInt(u16, port_str, 10) catch return error.MalformedSdp;

            _ = tokens.next() orelse return error.MalformedSdp;
            const pt_str = tokens.next() orelse return error.MalformedSdp;
            const pt = std.fmt.parseInt(u8, pt_str, 10) catch return error.MalformedSdp;
            payload_type = @truncate(pt);
        }
    }
    if (ip_addr.len == 0 or port == 0) {
        return error.MalformedSdp;
    }
    return .{ .ip_addr = ip_addr, .port = port, .payload_type = payload_type };
}

pub fn rewriteSdp(body: []const u8, new_ip: []const u8, new_port: u16, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).initCapacity(allocator, 128) catch return error.OutOfMemory;
    errdefer result.deinit(allocator);

    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len > 8 and std.mem.eql(u8, line[0..8], "c=IN IP4 ")) {
            try result.appendSlice(allocator, "c=IN IP4 ");
            try result.appendSlice(allocator, new_ip);
            try result.appendSlice(allocator, "\r\n");
        } else if (line.len > 8 and std.mem.eql(u8, line[0..8], "m=audio ")) {
            try result.appendSlice(allocator, "m=audio ");
            const port_str = try std.fmt.allocPrint(allocator, "{d}", .{new_port});
            defer allocator.free(port_str);
            try result.appendSlice(allocator, port_str);
            try result.appendSlice(allocator, " RTP/AVP ");
            const rest = line[18..];
            try result.appendSlice(allocator, rest);
            try result.appendSlice(allocator, "\r\n");
        } else {
            try result.appendSlice(allocator, line);
            try result.appendSlice(allocator, "\r\n");
        }
    }
    return try result.toOwnedSlice(allocator);
}

test "parse SDP basic" {
    const sdp =
        "v=0\r\n" ++
        "o=alice 123456 789 IN IP4 192.168.1.5\r\n" ++
        "s=Session\r\n" ++
        "c=IN IP4 192.168.1.5\r\n" ++
        "m=audio 8000 RTP/AVP 0\r\n";

    const info = try parseSdp(sdp);
    try std.testing.expectEqualStrings("192.168.1.5", info.ip_addr);
    try std.testing.expectEqual(@as(u16, 8000), info.port);
    try std.testing.expectEqual(@as(u7, 0), info.payload_type);
}

// test "debug SDP" {
//     const sdp =
//         "v=0\r\n" ++
//         "o=alice 123456 789 IN IP4 192.168.1.5\r\n" ++
//         "s=Session\r\n" ++
//         "c=IN IP4 192.168.1.5\r\n" ++
//         "m=audio 8000 RTP/AVP 0\r\n";

//     var lines = std.mem.splitScalar(u8, sdp, '\n');
//     var count: usize = 0;
//     while (lines.next()) |raw_line| {
//         const line = std.mem.trim(u8, raw_line, "\r");
//         std.debug.print("Line {}: '{s}' (len={})\n", .{ count, line, line.len });
//         if (line.len >= 9 and std.mem.eql(u8, line[0..9], "c=IN IP4 ")) {
//             std.debug.print("Found c line: '{s}'\n", .{line});
//         }
//         if (line.len >= 8 and std.mem.eql(u8, line[0..8], "m=audio ")) {
//             std.debug.print("Found m line: '{s}'\n", .{line});
//         }
//         count += 1;
//     }
// }
