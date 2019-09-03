const std = @import("std");
const builtin = @import("builtin");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    // b.verbose = true;
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zna", "src/main.zig");
    exe.setBuildMode(mode);
    
    const BPFObj = b.addSystemCommand( [_][]const u8{"objcopy","-I","elf64-little","-O","binary","--only-section=.text","zig-cache/bin/bpf.o","zig-cache/bin/bpf.bin" } );
    
    const BPF = b.addObject("bpf", "src/xdp_bpf.zig");
    BPF.disable_gen_h = true;
    BPF.strip = true;
    BPF.single_threaded = true;
    BPF.setTarget(.bpfel, .freestanding, .none);
    BPF.setBuildMode(.ReleaseFast);
    BPF.setOutputDir("zig-cache/bin/");
    BPF.verbose_cc = true;

    exe.step.dependOn(&BPFObj.step);
    BPFObj.step.dependOn(&BPF.step);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
