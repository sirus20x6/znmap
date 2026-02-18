const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Phase 1: SIMD IP Checksum
    const checksum = b.addObject(.{
        .name = "checksum",
        .root_source_file = b.path("checksum.zig"),
        .target = target,
        .optimize = optimize,
    });
    checksum.root_module.link_libc = true;
    b.installArtifact(checksum);

    // Convenience step: build all zig objects
    const all_step = b.step("all", "Build all Zig object files");
    all_step.dependOn(&checksum.step);
}
