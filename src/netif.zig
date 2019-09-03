const std = @import("std");
pub usingnamespace std.os.linux;

const kerror = @import("kerror.zig");
const config = @import("config.zig");

pub var if_cap_id: u32 = undefined;
pub var if_out_id: u32 = undefined;

pub fn init() anyerror!void {
    if_cap_id = try nameToIndex(config.if_cap_name);
    if (config.IPS)
        if_out_id = try nameToIndex(config.if_out_name);

    // Set the number of if queues to the number of workers
    // TODO

    // TODO
    // set promisc, LRO...
    // rx tx queues, hashes, and whatnot
    // activate various ricer optimizations maybe
}

pub fn deinit() void {
    // noop for now
}

fn nameToIndex(name: []const u8) anyerror!u32 {
    if (name.len > 15)
        return error.InterfaceNameTooLong;

    const _fd = try kerror.toError(socket(AF_INET, SOCK_STREAM, 0));
    const fd = @intCast(i32, _fd);
    defer _ = close(fd);

    const Ifreq = extern struct {
        name: [16]u8,
        index: i32,
        padding: [20]u8,
    };
    var ifreq = Ifreq{
        .name = [_]u8{0} ** 16,
        .index = 0,
        .padding = [_]u8{0} ** 20,
    };
    std.mem.copy(u8, ifreq.name[0..name.len], name[0..]);

    const SIOCGIFINDEX: usize = 0x8933;
    _ = kerror.toError(syscall3(SYS_ioctl, @intCast(usize, fd), SIOCGIFINDEX, @ptrToInt(&ifreq))) catch |err| switch (err) {
        error.Errno19_ENODEV => {
            std.debug.warn("The specificed network interface \"{}\" does not exist.\n", name);
            return err;
        },
        else => {
            return err;
        },
    };

    return @intCast(u32, ifreq.index);
}

// TODO
fn setPromisc(fd: i32, if_id: i32) anyerror!void {
    const mreq = packet_mreq{
        .mr_ifindex = if_id,
        .mr_type = 1, // PACKET_MR_PROMISC,
        .mr_alen = 0,
        .mr_address = [_]u8{0} ** 8,
    };

    const PACKET_ADD_MEMBERSHIP = 1;
    _ = try kerror.toError(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, @ptrCast([*]const u8, &mreq), @sizeOf(packet_mreq)));
}
