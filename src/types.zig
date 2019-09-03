// Some types not (yet?) in the zig std lib

pub const PR_SET_NAME: usize = 15;

pub const AF_XDP: usize = 44;
pub const PF_XDP: usize = 44;
pub const SOL_XDP: usize = 283;

pub const XDP_MMAP_OFFSETS: usize = 1;
pub const XDP_RX_RING: usize = 2;
pub const XDP_TX_RING: usize = 3;
pub const XDP_UMEM_REG: usize = 4;
pub const XDP_UMEM_FILL_RING: usize = 5;
pub const XDP_UMEM_COMPLETION_RING: usize = 6;
pub const XDP_STATISTICS: usize = 7;

pub const XDP_SHARED_UMEM: usize = (1 << 0);
pub const XDP_COPY: usize = (1 << 1);
pub const XDP_ZEROCOPY: usize = (1 << 2);

pub const XDP_PGOFF_RX_RING: usize = 0;
pub const XDP_PGOFF_TX_RING: usize = 0x80000000;
pub const XDP_UMEM_PGOFF_FILL_RING: usize = 0x100000000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: usize = 0x180000000;

pub const MAP_HUGE_SHIFT: usize = 26;

pub const sockaddr_xdp = extern struct {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
};

pub const xdp_umem_reg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
};

pub const xdp_ring_offset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
};

pub const xdp_mmap_offsets = extern struct {
    rx: xdp_ring_offset,
    tx: xdp_ring_offset,
    fr: xdp_ring_offset,
    cr: xdp_ring_offset,
};

pub const sockaddr_ll = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

pub const packet_mreq = extern struct {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [8]u8,
};

pub const bpf_attr_prog_load = extern struct {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64, // pub const struct bpf_insn *
    license: u64, // pub const char *
    log_level: u32,
    log_size: u32,
    log_buf: u64, // char *
    kern_version: u32,
    prog_flags: u32,
    prog_name: [16]u8,
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
};

pub const bpf_attr_map_create = extern struct {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
};

pub const bpf_attr_map_elem = extern struct {
    map_fd: i32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
};

pub const sockaddr_nl = extern struct {
    nl_family: u16,
    pad: u16,
    nl_pid: i32,
    nl_groups: u32,
};

pub const ifinfomsg = extern struct {
    ifi_family: u8,
    pad0: u8,
    ifi_type: u16,
    ifi_index: u32,
    ifi_flags: u32,
    ifi_change: u32,
};

pub const nlmsghdr = extern struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

pub const nlmsgerr = extern struct {
    errorcode: i32,
    msg: nlmsghdr,
};

pub const nlattr = extern struct {
    nla_len: u16,
    nla_type: u16,
};

pub const NETLINK_ROUTE: usize = 0;
pub const RTM_SETLINK: usize = 19;
pub const NLM_F_REQUEST: usize = 1;
pub const NLM_F_ACK: usize = 4;
pub const NLA_F_NESTED: usize = 32768;
pub const IFLA_XDP: usize = 43;
pub const NLA_HDRLEN: usize = 4;
pub const IFLA_XDP_FD: usize = 1;
pub const NLM_F_MULTI: usize = 2;
pub const NLMSG_ERROR: usize = 2;
pub const NLMSG_DONE: usize = 3;

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_TYPE_XDP: u32 = 6;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;

pub const BPF_MAP_TYPE_DEVMAP: usize = 14;
pub const BPF_MAP_TYPE_XSKMAP: usize = 17;

pub const bpf_insn = packed struct {
    code: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: i32,
};

pub const XDP_ABORTED: i32 = 0;
pub const XDP_DROP: i32 = 1;
pub const XDP_PASS: i32 = 2;
pub const XDP_TX: i32 = 3;
pub const XDP_REDIRECT: i32 = 4;

pub const xdp_md = extern struct {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
};

pub const xdp_desc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

pub var bpf_redirect_map: extern fn (*i32, u32, u32) i32 = @intToPtr(extern fn (*i32, u32, u32) i32, 51);
