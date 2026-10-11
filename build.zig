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
    const strip_wanted = b.option(bool, "strip", "Leave debug information out of the binary");

    // Except on aarch64 Windows, where a stripped build crashes at its first
    // thread-local access. Stripping drops the local symbols, so the compiler
    // addresses each thread-local variable as an offset into the .tls section,
    // and puts that offset in the instruction that relocates the upper bits.
    // The linker in Zig 0.16 (LLD from LLVM 21) reads that offset as a count of
    // 4 KiB pages rather than bytes, so a variable 8 bytes in is looked for
    // 32 KiB in. LLD fixed this in llvm/llvm-project#200060, and the exception
    // can go once the pinned Zig links with an LLD that has the fix. Little is
    // lost meanwhile: a Windows binary keeps its debug information in a .pdb
    // beside it, which the release does not ship, so the .exe only grows by
    // the stack trace code, about 250 KB.
    const strip = if (target.result.os.tag == .windows and target.result.cpu.arch == .aarch64)
        false
    else
        strip_wanted;

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

    // `zig build test -Dtest-filter=<substr>` runs only the tests whose names
    // contain the text.
    const test_filter = b.option([]const u8, "test-filter", "Run only the tests whose name contains this text");
    const exe_tests = b.addTest(.{
        .name = "deed-test",
        .root_module = exe_mod,
        .filters = if (test_filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);

    // `zig build test-bin -Dtarget=<target>` builds the tests into
    // zig-out/bin/deed-test without running them, for a machine that can run
    // that target but not build it. CI uses it for aarch64 Windows.
    const install_tests = b.addInstallArtifact(exe_tests, .{});
    const test_bin_step = b.step("test-bin", "Build the unit tests without running them");
    test_bin_step.dependOn(&install_tests.step);
}
