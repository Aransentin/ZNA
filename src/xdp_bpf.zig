pub usingnamespace @import("types.zig");

var dummy: i32 = 0;

export fn bpf_main(ctx: *xdp_md) i32 {
    const queue = ctx.rx_queue_index;
    return bpf_redirect_map(&dummy, queue, 0);
}
