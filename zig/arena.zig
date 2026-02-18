// Arena memory allocator — bump allocator with bulk reset.
// Eliminates per-packet malloc/free churn in checksum and probe paths.
//
// C ABI exports:
//   arena_create(size)  — allocate arena with given backing size
//   arena_alloc(h, sz)  — bump-allocate sz bytes (16-byte aligned)
//   arena_reset(h)      — reset to start (free all at once)
//   arena_destroy(h)    — free all backing memory

const std = @import("std");

const Arena = struct {
    base: [*]u8,
    capacity: usize,
    offset: usize,
};

export fn arena_create(size: usize) callconv(.c) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    const arena = allocator.create(Arena) catch return null;
    const mem = allocator.alloc(u8, size) catch {
        allocator.destroy(arena);
        return null;
    };
    arena.* = Arena{
        .base = mem.ptr,
        .capacity = size,
        .offset = 0,
    };
    return @ptrCast(arena);
}

export fn arena_alloc(handle: ?*anyopaque, size: usize) callconv(.c) ?[*]u8 {
    const arena: *Arena = @ptrCast(@alignCast(handle orelse return null));
    // Align to 16 bytes
    const aligned_offset = (arena.offset + 15) & ~@as(usize, 15);
    if (aligned_offset + size > arena.capacity) return null;
    const ptr = arena.base + aligned_offset;
    arena.offset = aligned_offset + size;
    return ptr;
}

export fn arena_reset(handle: ?*anyopaque) callconv(.c) void {
    const arena: *Arena = @ptrCast(@alignCast(handle orelse return));
    arena.offset = 0;
}

export fn arena_destroy(handle: ?*anyopaque) callconv(.c) void {
    const arena: *Arena = @ptrCast(@alignCast(handle orelse return));
    const allocator = std.heap.c_allocator;
    allocator.free(arena.base[0..arena.capacity]);
    allocator.destroy(arena);
}
