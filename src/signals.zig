const std = @import("std");

pub var flag: u8 = 0;
threadlocal var mainthread: bool = false;

extern fn handleSIGINT(sig: i32, info: *const std.os.siginfo_t, ctx_ptr: *const c_void) void {
    if (!mainthread)
        return;

    if (flag == 1) {
        std.debug.warn("Caught second SIGINT, shutting down immediately\n");
        std.os.exit(1);
    }
    std.debug.warn("Caught SIGINT, shutting down gracefully\n");
    flag = 1;
}

pub fn init() anyerror!void {
    mainthread = true;
    var act = std.os.Sigaction{
        .sigaction = handleSIGINT,
        .mask = std.os.empty_sigset,
        .flags = std.os.SA_SIGINFO,
    };
    std.os.sigaction(std.os.SIGINT, &act, null);
}
