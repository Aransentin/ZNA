const std = @import("std");
pub usingnamespace std.os.linux;
pub usingnamespace @import("types.zig");

const config = @import("config.zig");
const netif = @import("netif.zig");
const kerror = @import("kerror.zig");

var bpffd: i32 = 0;
var xskmapfd: i32 = 0;

pub fn init() anyerror!void {

    // Yeet the previous BPF program should we have crashed or something
    // attachXDPIF(netif.if_cap_id, -1) catch |err| {};
    const map_attr = bpf_attr_map_create{
        .map_type = BPF_MAP_TYPE_XSKMAP,
        .key_size = 4,
        .value_size = 4,
        .max_entries = config.workers.len,
        .map_flags = 0,
    };

    const _xskmapfd_usize = try kerror.toError(syscall3(SYS_bpf, BPF_MAP_CREATE, @ptrToInt(&map_attr), @sizeOf(bpf_attr_map_create)));
    const _xskmapfd = @intCast(i32, _xskmapfd_usize);
    errdefer _ = close(_xskmapfd);

    var bpfbin = @embedFile("../zig-cache/bin/bpf.bin");
    var bpfi = @ptrCast([*]bpf_insn, &bpfbin);

    var i: usize = 0;
    while (i < bpfbin.len / 8) : (i += 1) {
        var ins = &bpfi[i];

        // std.debug.warn( "REG: {}\n", ins );
        // Not a great solution. Will start failing when we get more map types...
        if (ins.code == 0x18 and ins.dst == 1 and ins.imm == 0) {
            ins.src = 1;
            ins.imm = _xskmapfd;
        }
    }

    var logbuf = [_]u8{0} ** 2049;
    const bpf_attr = bpf_attr_prog_load{
        .prog_type = BPF_PROG_TYPE_XDP,
        .insn_cnt = bpfbin.len / 8,
        .insns = @ptrToInt(bpfi),
        .log_level = 1,
        .log_size = logbuf.len - 1,
        .log_buf = @ptrToInt(&logbuf),
        .license = @ptrToInt(c""),
        .kern_version = 0,
        .prog_flags = 0,
        .prog_name = [_]u8{0} ** 16,
        .prog_ifindex = 0,
        .expected_attach_type = 0,
        .prog_btf_fd = 0,
        .func_info_rec_size = 0,
        .func_info = 0,
        .func_info_cnt = 0,
        .line_info_rec_size = 0,
        .line_info = 0,
        .line_info_cnt = 0,
    };
    const _bpffd_usize = kerror.toError(syscall3(SYS_bpf, BPF_PROG_LOAD, @ptrToInt(&bpf_attr), @sizeOf(bpf_attr_prog_load))) catch |err| {
        const buflen = std.mem.len(u8, &logbuf);
        if (buflen > 0)
            std.debug.warn("XDP BPF error log:\n{}\n", logbuf[0..buflen]);
        return err;
    };
    const _bpffd = @intCast(i32, _bpffd_usize);
    errdefer _ = close(_bpffd);

    try attachXDPIF(netif.if_cap_id, _bpffd);

    bpffd = _bpffd;
    xskmapfd = _xskmapfd;
}

pub fn deinit() void {
    attachXDPIF(netif.if_cap_id, -1) catch |err| {};
    if (bpffd > 0) {
        _ = close(bpffd);
    }
    if (xskmapfd > 0) {
        _ = close(xskmapfd);
    }
}

fn attachXDPIF(interface: u32, fd: i32) anyerror!void {
    const _nlfd = try kerror.toError(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
    const nlfd = @intCast(i32, _nlfd);
    defer _ = close(nlfd);

    const saddr = sockaddr_nl{
        .nl_family = AF_NETLINK,
        .pad = 0,
        .nl_pid = 0,
        .nl_groups = 0,
    };

    _ = try kerror.toError(bind(nlfd, @ptrCast(*const sockaddr, &saddr), @sizeOf(sockaddr_nl)));

    const req = extern struct {
        nh: nlmsghdr,
        ifinfo: ifinfomsg,
        attrbuf: [64]u8,
    };

    var reqv = req{
        .nh = nlmsghdr{
            .nlmsg_len = @sizeOf(ifinfomsg) + @sizeOf(nlmsghdr),
            .nlmsg_type = RTM_SETLINK,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
            .nlmsg_seq = 0,
            .nlmsg_pid = 0,
        },
        .ifinfo = ifinfomsg{
            .ifi_family = AF_UNSPEC,
            .ifi_index = interface,
            .ifi_type = 0,
            .ifi_flags = 0,
            .ifi_change = 0,
            .pad0 = 0,
        },
        .attrbuf = [_]u8{0} ** 64,
    };

    var nla = @ptrCast(*nlattr, @ptrCast([*]u8, &reqv) + reqv.nh.nlmsg_len);
    nla.nla_type = NLA_F_NESTED | IFLA_XDP;
    nla.nla_len = NLA_HDRLEN;

    var nla_xdp = @ptrCast(*nlattr, @ptrCast([*]u8, nla) + nla.nla_len);
    nla_xdp.nla_type = IFLA_XDP_FD;
    nla_xdp.nla_len = NLA_HDRLEN + @sizeOf(i32);

    var xdpfdp = @ptrCast(*i32, @ptrCast([*]u8, nla_xdp) + NLA_HDRLEN);
    xdpfdp.* = fd;
    nla.nla_len += nla_xdp.nla_len;
    reqv.nh.nlmsg_len += nla.nla_len;

    _ = sendto(nlfd, @ptrCast([*]u8, &reqv), reqv.nh.nlmsg_len, MSG_WAITALL, null, 0);

    var multipart = true;
    while (multipart == true) {
        multipart = false;

        // LibBPF does 4096 bytes too, should be enough..!
        var buf: [4096]u8 align(@alignOf(nlmsghdr)) = [_]u8{0} ** 4096;
        const nb = try kerror.toError(recvfrom(nlfd, &buf, buf.len, 0, null, null));

        if (nb == 0)
            break;

        if (nb < @sizeOf(nlmsghdr)) {
            std.debug.warn("Expected >= @sizeOf(nlmsghdr) for AF_NETLINK response ({} bytes) but got {}, cannot determine if BFP program is loaded\n", u32(@sizeOf(nlmsghdr)), nb);
            return error.ResponseTooSmall;
        }

        var bp: u32 = 0;
        while (bp != nb) {
            bp = (bp + 3) & (~u32(3)); // NLMSG_ALIGN

            if ((nb - bp) < @sizeOf(nlmsghdr)) {
                // Huh. Whatever.
                break;
            }

            const header = @ptrCast(*nlmsghdr, @alignCast(4, &buf[bp]));
            if (header.nlmsg_len < @sizeOf(nlmsghdr)) {
                std.debug.warn("Expected header.nlmsg_len >= @sizeOf(nlmsghdr) for AF_NETLINK response ({} bytes) but got {}, cannot determine if BFP program is loaded\n", u32(@sizeOf(nlmsghdr)), header.nlmsg_len);
                return error.ResponseError;
            }

            bp += @sizeOf(nlmsghdr);
            if (header.nlmsg_flags & NLM_F_MULTI != 0)
                multipart = true;

            switch (header.nlmsg_type) {
                NLMSG_ERROR => {
                    const err = @ptrCast(*nlmsgerr, @alignCast(4, &buf[bp]));
                    _ = kerror.toError(@intCast(usize, err.errorcode)) catch |errv| {
                        // TODO: dump extended TLV error string?
                        std.debug.warn("BPF program load failed with {}\n", errv);
                        return error.BFPLoadFailed;
                    };
                },
                NLMSG_DONE => {
                    return;
                },
                else => {},
            }
            bp += (header.nlmsg_len - @sizeOf(nlmsghdr));
        }
    }
}

pub fn attachWorker(key: u32, fd: i32) anyerror!void {
    var map_attr = bpf_attr_map_elem{
        .map_fd = xskmapfd,
        .key = @ptrToInt(&key),
        .value = @ptrToInt(&fd),
        .flags = 0,
        .pad = 0,
    };
    _ = try kerror.toError(syscall3(SYS_bpf, BPF_MAP_UPDATE_ELEM, @ptrToInt(&map_attr), @sizeOf(bpf_attr_map_elem)));
}
