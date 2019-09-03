const std = @import("std");
const xdp = @import("xdp.zig");
const netif = @import("netif.zig");
const config = @import("config.zig");
const signals = @import("signals.zig");
const worker = @import("worker.zig");

pub fn main() anyerror!void {
    try rmain();
    // cleanup to make valgrind output nicer
    _ = std.os.linux.close(2);
    _ = std.os.linux.close(1);
    _ = std.os.linux.close(0);
}

fn rmain() anyerror!void {
    try signals.init();

    try netif.init();
    defer netif.deinit();

    try xdp.init();
    defer xdp.deinit();

    try worker.initWorkers();
    defer worker.deinitWorkers();

    try worker.runWorkers();
    defer worker.stopWorkers();

    while (signals.flag == 0) {
        // hmmm... wake this on SIGINT... epoll should do it?
        std.time.sleep(100000000);
    }
}
