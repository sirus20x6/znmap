const std = @import("std");

const module_names = [_][]const u8{
    "checksum",
    "probe_filter",
    "arena",
    "portstate",
    "aho_corasick",
    "dns_pool",
    "fp_match",
    "pkt_builder",
};

const module_srcs = [_][]const u8{
    "checksum.zig",
    "probe_filter.zig",
    "arena.zig",
    "portstate.zig",
    "aho_corasick.zig",
    "dns_pool.zig",
    "fp_match.zig",
    "pkt_builder.zig",
};

const cross_triples = [_]struct {
    name: []const u8,
    cpu: std.Target.Cpu.Arch,
    os: std.Target.Os.Tag,
    abi: std.Target.Abi,
}{
    .{ .name = "x86_64-linux-gnu", .cpu = .x86_64, .os = .linux, .abi = .gnu },
    .{ .name = "aarch64-linux-gnu", .cpu = .aarch64, .os = .linux, .abi = .gnu },
    .{ .name = "x86_64-macos-none", .cpu = .x86_64, .os = .macos, .abi = .none },
    .{ .name = "aarch64-macos-none", .cpu = .aarch64, .os = .macos, .abi = .none },
    .{ .name = "x86_64-windows-gnu", .cpu = .x86_64, .os = .windows, .abi = .gnu },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const all_step = b.step("all", "Build all Zig object files");

    // Native object targets — one per module
    for (module_names, module_srcs) |name, src| {
        const mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        const obj = b.addObject(.{
            .name = name,
            .root_module = mod,
        });

        // Install .o into zig-out/lib/<name>.o
        const install = b.addInstallFileWithDir(
            obj.getEmittedBin(),
            .lib,
            b.fmt("{s}.o", .{name}),
        );

        // Per-module step:  zig build checksum
        const mod_step = b.step(name, b.fmt("Build {s} object file", .{name}));
        mod_step.dependOn(&install.step);

        all_step.dependOn(&install.step);
    }

    // Default install builds everything
    b.getInstallStep().dependOn(all_step);

    // Cross-compilation step: zig build cross -Doptimize=ReleaseFast
    const cross_step = b.step("cross", "Build all modules for all cross-compilation targets");

    for (cross_triples) |ct| {
        const cross_target = b.resolveTargetQuery(.{
            .cpu_arch = ct.cpu,
            .os_tag = ct.os,
            .abi = ct.abi,
        });

        for (module_names, module_srcs) |name, src| {
            const mod = b.createModule(.{
                .root_source_file = b.path(src),
                .target = cross_target,
                .optimize = optimize,
                .link_libc = true,
            });

            const obj = b.addObject(.{
                .name = name,
                .root_module = mod,
            });

            // Install into zig-out/<triple>/<name>.o
            const install = b.addInstallFileWithDir(
                obj.getEmittedBin(),
                .{ .custom = ct.name },
                b.fmt("{s}.o", .{name}),
            );
            cross_step.dependOn(&install.step);
        }
    }
}
