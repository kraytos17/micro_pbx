//! Test-only allocation counter. Wraps a parent allocator and counts
//! alloc/free calls plus allocated bytes (not high-water). Measure with
//! page_allocator as parent: SafeAllocator never reuses memory and would
//! inflate every number.

const std = @import("std");

pub const Counting = struct {
    parent: std.mem.Allocator,
    allocs: usize = 0,
    frees: usize = 0,
    bytes_allocated: usize = 0,

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    pub fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn outstanding(self: *const Counting) usize {
        return self.allocs - self.frees;
    }

    fn allocFn(ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.allocs += 1;
        self.bytes_allocated += len;
        return std.mem.Allocator.rawAlloc(self.parent, len, alignment, ret_addr);
    }

    fn remapFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.bytes_allocated += new_len -| memory.len;
        return std.mem.Allocator.rawRemap(self.parent, memory, alignment, new_len, ret_addr);
    }

    fn freeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.frees += 1;
        return std.mem.Allocator.rawFree(self.parent, memory, alignment, ret_addr);
    }

    fn resizeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        return std.mem.Allocator.rawResize(self.parent, memory, alignment, new_len, ret_addr);
    }
};

test "counting allocator passes through" {
    var counting = Counting{ .parent = std.heap.page_allocator };
    const alloc = counting.allocator();
    const mem = try alloc.alloc(u8, 64);
    try std.testing.expectEqual(@as(usize, 1), counting.allocs);
    alloc.free(mem);
    try std.testing.expectEqual(@as(usize, 1), counting.frees);
    try std.testing.expectEqual(@as(usize, 0), counting.outstanding());
}
