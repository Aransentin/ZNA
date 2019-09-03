const std = @import("std");
const builtin = @import("builtin");
pub usingnamespace std.os.linux;
pub usingnamespace @import("types.zig");

const kerror = @import("kerror.zig");
const config = @import("config.zig");
const netif = @import("netif.zig");
const xdp = @import("xdp.zig");
const Flowhandler = @import("flowhandler.zig").Flowhandler;

var signal_exit: u8 = 0;

const page_size = 1 << config.page_log2;
const umem_size = config.MTU * config.npackets;
const umem_pages = ((umem_size - 1) / page_size) + 1;

const fill_queue_descs: usize = config.npackets;
const comp_queue_descs: usize = 8;
const rx_queue_descs: usize = config.npackets;
const tx_queue_descs: usize = 8;

const Worker = struct {
    thread: ?*std.Thread,

    queue: u32,
    cpu: u32,
    capfd: i32,
    outfd: if (config.IPS) i32 else void,
    epollfd: i32,

    umem: xdp_umem_reg,

    fq_map: [*]align(4096) u8,
    fq_desc_size: u32,
    fq_producer: *u64,
    fq_consumer: *u64,
    fq_ring: [*]u64,

    rx_map: [*]align(4096) u8,
    rx_desc_size: u32,
    rx_producer: *u64,
    rx_consumer: *u64,
    rx_ring: [*]xdp_desc,

    flowhandler: Flowhandler,

    fn init(self: *Worker, queue: u32, cpu: u32) anyerror!void {
        const _capfd = kerror.toError(socket(AF_XDP, SOCK_RAW, 0)) catch |err| switch (err) {
            error.Errno97_EAFNOSUPPORT => {
                return error.XDPNotSupported;
            },
            else => {
                return err;
            },
        };
        const capfd = @intCast(i32, _capfd);
        errdefer _ = close(capfd);

        if (config.busy_poll > 0) {
            if (kerror.toError(setsockopt(capfd, SOL_SOCKET, SO_BUSY_POLL, @ptrCast([*]const u8, &config.busy_poll), @sizeOf(usize)))) {} else |err| {
                if (queue == 0) { // No sense spamming this a zillion times
                    std.debug.warn("Could not set SO_BUSY_POLL to {} μs: {}. Performance may suffer.\n", config.busy_poll, err);
                }
            }
        }

        if (kerror.toError(setsockopt(capfd, SOL_SOCKET, SO_INCOMING_CPU, @ptrCast([*]const u8, &cpu), @sizeOf(u32)))) {} else |err| {
            std.debug.warn("Could not pin the incoming packets of queue {} to CPU {}: {}. Performance may suffer.\n", queue, cpu, err);
        }

        // Allocate memory for our packets
        const mmapflags: u64 = comptime fbrk: {
            if (config.page_log2 == 0) {
                @compileError("A page size of 0 doesn't make sense");
            }
            var flags: u64 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_POPULATE | MAP_UNINITIALIZED;
            if (config.page_log2 >= 16) {
                flags |= MAP_HUGETLB | (config.page_log2 << MAP_HUGE_SHIFT);
            }
            break :fbrk flags;
        };

        const _umem_map: usize = try kerror.toError(mmap(null, umem_size, PROT_READ | PROT_WRITE, mmapflags, -1, 0));
        const umem_map = @intToPtr([*]u8, _umem_map);
        errdefer _ = munmap(umem_map, umem_size);

        // mmap can return success even if it failed to allocate hugepages (yes, even though we've got MAP_POPULATE) so we need to check manually
        if (config.page_log2 >= 16) {
            var i: usize = 0;
            while (i < umem_pages) : (i += 1) {
                const memp = _umem_map + i * page_size;
                var mincore_flag: u8 = 0;
                _ = try kerror.toError(syscall3(SYS_mincore, memp, 1, @ptrToInt(&mincore_flag)));
                if (mincore_flag & 0x01 == 0) {
                    return error.OutOfHugePages;
                }
            }
        }

        // Setup UMEM packet buffer
        const umem = xdp_umem_reg{
            .addr = _umem_map,
            .len = umem_size,
            .chunk_size = umem_size / fill_queue_descs,
            .headroom = 0,
        };
        _ = try kerror.toError(setsockopt(capfd, SOL_XDP, XDP_UMEM_REG, @ptrCast([*]const u8, &umem), @sizeOf(xdp_umem_reg)));

        // Setup rings
        _ = try kerror.toError(setsockopt(capfd, SOL_XDP, XDP_UMEM_FILL_RING, @ptrCast([*]const u8, &fill_queue_descs), @sizeOf(usize)));
        _ = try kerror.toError(setsockopt(capfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, @ptrCast([*]const u8, &comp_queue_descs), @sizeOf(usize)));
        _ = try kerror.toError(setsockopt(capfd, SOL_XDP, XDP_RX_RING, @ptrCast([*]const u8, &rx_queue_descs), @sizeOf(usize)));
        _ = try kerror.toError(setsockopt(capfd, SOL_XDP, XDP_TX_RING, @ptrCast([*]const u8, &tx_queue_descs), @sizeOf(usize)));

        var xdpoffset: xdp_mmap_offsets = undefined;
        var xdpoffset_len: u32 = @sizeOf(xdp_mmap_offsets);
        _ = try kerror.toError(getsockopt(capfd, SOL_XDP, XDP_MMAP_OFFSETS, @ptrCast([*]u8, &xdpoffset), &xdpoffset_len));

        const _fq_map = try kerror.toError(mmap(null, xdpoffset.fr.desc + fill_queue_descs * @sizeOf(u64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, capfd, XDP_UMEM_PGOFF_FILL_RING));
        const fq_map = @intToPtr([*]align(4096) u8, _fq_map);
        errdefer _ = munmap(@ptrCast([*]u8, fq_map), xdpoffset.fr.desc + fill_queue_descs * @sizeOf(u64));
        const fq_producer: *u64 = @ptrCast(*u64, @alignCast(8, fq_map + xdpoffset.fr.producer));
        const fq_consumer: *u64 = @ptrCast(*u64, @alignCast(8, fq_map + xdpoffset.fr.consumer));
        const fq_ring: [*]u64 = @ptrCast([*]u64, @alignCast(8, fq_map + xdpoffset.fr.desc));

        const _rx_map = try kerror.toError(mmap(null, xdpoffset.rx.desc + rx_queue_descs * @sizeOf(xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, capfd, XDP_PGOFF_RX_RING));
        const rx_map = @intToPtr([*]align(4096) u8, _rx_map);
        errdefer _ = munmap(@ptrCast([*]u8, rx_map), xdpoffset.rx.desc + rx_queue_descs * @sizeOf(xdp_desc));
        const rx_producer: *u64 = @ptrCast(*u64, @alignCast(8, rx_map + xdpoffset.rx.producer));
        const rx_consumer: *u64 = @ptrCast(*u64, @alignCast(8, rx_map + xdpoffset.rx.consumer));
        const rx_ring: [*]xdp_desc = @ptrCast([*]xdp_desc, @alignCast(8, rx_map + xdpoffset.rx.desc));

        // Fill addresses
        const framesize = umem_size / fill_queue_descs;
        var ai: usize = 0;
        while (ai < fill_queue_descs) : (ai += 1) {
            fq_ring[ai] = ai * framesize;
        }

        // Tell the kernel the fq_ring is available
        fq_producer.* = fill_queue_descs;

        // Bind!

        // TODO: getsockopt(xsk->fd, SOL_XDP, XDP_OPTIONS, &opts, &optlen);
        // xsk->zc = opts.flags & XDP_OPTIONS_ZEROCOPY;

        var sxdp = sockaddr_xdp{
            .sxdp_family = PF_XDP,
            .sxdp_ifindex = netif.if_cap_id,
            .sxdp_queue_id = queue,
            .sxdp_flags = XDP_ZEROCOPY,
            .sxdp_shared_umem_fd = 0,
        };
        _ = kerror.toError(bind(capfd, @ptrCast(*const sockaddr, &sxdp), @sizeOf(sockaddr_xdp))) catch |err| switch (err) {
            error.Errno95_EOPNOTSUPP => ret: {
                if (queue == 0) { // No sense spamming this a zillion times
                    std.debug.warn("XDP_ZEROCOPY unsupported, continuing with XDP_COPY\n");
                }
                sxdp.sxdp_flags = XDP_COPY;
                _ = try kerror.toError(bind(capfd, @ptrCast(*const sockaddr, &sxdp), @sizeOf(sockaddr_xdp)));
                break :ret 0;
            },
            error.Errno16_EBUSY => {
                // Somebody hogged our queue, notify user and don't just crash with a cryptic EBUSY
                return err;
            },
            else => {
                return err;
            },
        };

        // Epoll
        const _epollfd = try kerror.toError(epoll_create1(0));
        const epollfd = @intCast(i32, _epollfd);
        errdefer _ = close(epollfd);

        var ep_event_cap = epoll_event{
            .events = EPOLLIN | EPOLLET,
            .data = epoll_data{ .u64 = 0 },
        };
        _ = try kerror.toError(epoll_ctl(epollfd, EPOLL_CTL_ADD, capfd, &ep_event_cap));

        // Add ourselves to the XSKMAP
        try xdp.attachWorker(queue, capfd);

        // Init subsystems
        try self.flowhandler.init();

        // Done!
        self.queue = queue;
        self.cpu = cpu;
        self.capfd = capfd;
        self.epollfd = epollfd;
        self.thread = null;
        if (config.IPS) {
            // outfd
        }
        self.umem = umem;
        self.fq_map = fq_map;
        self.fq_desc_size = @intCast(u32, xdpoffset.fr.desc);
        self.fq_producer = fq_producer;
        self.fq_consumer = fq_consumer;
        self.fq_ring = fq_ring;

        self.rx_map = rx_map;
        self.rx_desc_size = @intCast(u32, xdpoffset.rx.desc);
        self.rx_producer = rx_producer;
        self.rx_consumer = rx_consumer;
        self.rx_ring = rx_ring;
    }
    fn deinit(self: *Worker) void {
        self.flowhandler.deinit();

        _ = close(self.capfd);
        if (config.IPS)
            _ = close(self.outfd);
        _ = close(self.epollfd);

        _ = munmap(@intToPtr([*]u8, self.umem.addr), self.umem.len);
        _ = munmap(@ptrCast([*]u8, self.fq_map), self.fq_desc_size + fill_queue_descs * @sizeOf(u64));
        _ = munmap(@ptrCast([*]u8, self.rx_map), self.rx_desc_size + rx_queue_descs * @sizeOf(xdp_desc));
    }

    fn run(self: *Worker) anyerror!void {
        self.thread = try std.Thread.spawn(self, thread);
    }

    fn stop(self: *Worker) void {
        const thrd = self.thread orelse return;
        _ = syscall2(SYS_tkill, @intCast(usize, thrd.handle()), SIGINT);
        thrd.wait();
        std.debug.warn("Thread {} exited with {} packets processed\n", self.queue, self.rx_consumer.*);
    }

    fn thread(self: *Worker) void {
        var CPUs = [_]u8{0} ** 128;

        // Set thread name
        var namebuf = [_]u8{0} ** 16;
        _ = std.fmt.bufPrint(namebuf[0..], "worker {}", self.queue) catch |err| brk: {
            std.mem.copy(u8, namebuf[0..16], "worker");
            break :brk null;
        };

        if (kerror.toError(syscall2(SYS_prctl, PR_SET_NAME, @ptrToInt(&namebuf)))) |_| {} else |err| {
            std.debug.warn("Failed to set thread name for worker {}: {}\n", self.queue, err);
        }

        // Set CPU affinity
        if (self.cpu > (CPUs.len * 8 - 1)) {
            std.debug.warn("Invalid CPU ({}) specified for worker {}.\n", self.cpu, self.queue);
        } else {
            const bitp = &CPUs[self.cpu >> 3];
            bitp.* = @intCast(u8, self.cpu & 0x07);
            if (kerror.toError(syscall3(SYS_sched_setaffinity, 0, @sizeOf(@typeOf(CPUs)), @ptrToInt(&CPUs)))) |_| {} else |err| {
                std.debug.warn("Failed to set affinity for worker {} on CPU {}: {}\n", self.queue, self.cpu, err);
            }
        }

        while (@atomicLoad(u8, &signal_exit, .SeqCst) == 0) {
            const nevents: usize = if (config.IPS) 2 else 1;
            var events: [nevents]epoll_event = [_]epoll_event{epoll_event{ .events = 0, .data = epoll_data{ .u64 = 0 } }} ** nevents;
            const nv = kerror.toError(epoll_pwait(self.epollfd, &events, nevents, 1000, null)) catch |err| {
                // TODO: Megafail, bail the entire program
                return;
            };

            var i: usize = 0;
            while (i < nv) : (i += 1) {
                if (events[i].data.u64 == 0) {

                    // TODO: Periodically(?) check if we've capped the packet buffer here
                    self.handleRx();
                }
            }

            //std.debug.warn("{}:{} :: {}:{}\n", self.rx_producer.*, self.rx_consumer.*, self.fq_producer.*, self.fq_consumer.*);
        }
    }

    fn handleRx(self: *Worker) void {
        const rxp = self.rx_producer.*;
        var rxc = self.rx_consumer.*;
        var fqp = self.fq_producer.*;

        while (rxc != rxp) {
            const pdsc = self.rx_ring[rxc & (rx_queue_descs - 1)];
            const pptr = @intToPtr([*]align(config.MTU) u8, self.umem.addr + pdsc.addr);
            const packet = pptr[0..pdsc.len];

            const ref = self.flowhandler.newPacket(packet);
            if (!ref) {
                self.fq_ring[fqp & (fill_queue_descs - 1)] = pdsc.addr;
                fqp += 1;
            }
            rxc += 1;
        }

        self.rx_consumer.* = rxc;
        self.fq_producer.* = fqp;
    }
};

var workers: [config.workers.len]Worker = undefined;

pub fn initWorkers() anyerror!void {
    var i: u32 = 0;
    while (i < config.workers.len) : (i += 1) {
        try workers[i].init(i, config.workers[i]);
    }
}

pub fn deinitWorkers() void {
    var i: u32 = 0;
    while (i < config.workers.len) : (i += 1) {
        workers[i].deinit();
    }
}

pub fn runWorkers() anyerror!void {
    var i: u32 = 0;
    while (i < config.workers.len) : (i += 1) {
        try workers[i].run();
    }
}

pub fn stopWorkers() void {
    _ = @atomicRmw(u8, &signal_exit, .Xchg, 1, .SeqCst);

    var i: u32 = 0;
    while (i < config.workers.len) : (i += 1) {
        workers[i].stop();
    }
}
