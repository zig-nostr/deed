const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The protocol library links libsecp256k1 and liblmdb, so the executable
    // links libc.
    const nostr_dep = b.dependency("nostr", .{
        .target = target,
        .optimize = optimize,
    });

    // Release builds pass -Dstrip. Without it a Linux binary carries about
    // nine megabytes of debug sections, three quarters of the file.
    const strip = b.option(bool, "strip", "Leave debug information out of the binary");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
    });
    exe_mod.addImport("nostr", nostr_dep.module("nostr"));

    const exe = b.addExecutable(.{
        .name = "deed",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run deed");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{ .root_module = exe_mod });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);
}
