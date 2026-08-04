//! PBX entry point: bootstrap and logging configuration.

const std = @import("std");
const pbx = @import("pbx.zig");

const log = std.log.scoped(.main);

/// Compile-time logging configuration for the whole PBX.
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = pbxLog,
};

/// Timestamped log formatter. Emits to stderr with color, prefixing each line
/// with a wall-clock `HH:MM:SS.mmm` timestamp.
fn pbxLog(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const io = std.Options.debug_io;
    const ts = std.Io.Timestamp.now(io, std.Io.Clock.real);

    const secs = ts.toSeconds();
    const ms: u64 = @intCast(@mod(ts.toMilliseconds(), 1000));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(secs, 0)) };
    const day_seconds = epoch_seconds.getDaySeconds();

    var buffer: [64]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer).terminal();
    defer std.debug.unlockStderr();

    stderr.setColor(switch (level) {
        .err => .red,
        .warn => .yellow,
        .info => .green,
        .debug => .magenta,
    }) catch {};
    stderr.setColor(.bold) catch {};
    stderr.writer.print("[{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}] {s}", .{
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        ms,
        level.asText(),
    }) catch return;
    stderr.setColor(.reset) catch {};
    stderr.setColor(.dim) catch {};
    stderr.setColor(.bold) catch {};
    if (scope != .default) stderr.writer.print("({t})", .{scope}) catch return;

    stderr.writer.print(": ", .{}) catch return;
    stderr.setColor(.reset) catch {};
    stderr.writer.print(format ++ "\n", args) catch return;
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var server = try pbx.Pbx.init(gpa.allocator(), init.io, 5060);
    defer server.deinit();

    log.info("PBX listening on 0.0.0.0:5060", .{});
    try server.run();
}

test {
    std.testing.refAllDecls(@This());
}
