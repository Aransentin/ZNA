const std = @import("std");
const config = @import("config.zig");
const mm = @import("mmap.zig");
pub usingnamespace std.os.linux;

// Move these structs etc. to some other file...
const ethertype_ipv4 = std.mem.nativeToBig(u16, 0x0800);
const ethertype_ipv6 = std.mem.nativeToBig(u16, 0x86DD);

const ethernet = packed struct {
    dst: [6]u8,
    src: [6]u8,
    type: u16,
};

// Note: Big-endian, some fields are flipped
const IPv4 = packed struct {
    IHL: u4,
    version: u4,
    ECN: u2,
    DSCP: u6,
    length: u16,
    identification: u16,
    flags: u16,
    TTL: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
};

const IPv6 = packed struct {
    // TODO
};

const UDP = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

const flowIP = if (config.IPv6) u128 else u32;
const FlowKey = packed struct {
    ip0: flowIP,
    ip1: flowIP,
    port0: u16,
    port1: u16,
    proto: u8,
    pad: u24,
};
const Flow = packed struct {
    key: FlowKey,
    hash: u32,
    occupied: u1,
    dir: u1,
    // Flow data ptr...
};

comptime {
    if (@popCount(usize, config.flows) != 1) {
        @compileError("flows is not a power of 2");
    }
}

pub const Flowhandler = struct {
    flowmap_occupancy: u32,
    flowmap: [*]align(4096) Flow,

    pub fn init(self: *Flowhandler) anyerror!void {
        const _flowmap = try mm.mmap_huge(config.flows * @sizeOf(Flow), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_POPULATE);
        errdefer _ = munmap(umem_map, _flowmap);
        self.flowmap = @ptrCast([*]align(4096) Flow, _flowmap);
        self.flowmap_occupancy = 0;
    }
    pub fn deinit(self: *Flowhandler) void {
        _ = munmap(@ptrCast([*]u8, self.flowmap), config.flows * @sizeOf(Flow));
    }
    pub fn prune(self: *Flowhandler) void {
        // prune
    }
    fn flowKeyHash(fk: *const FlowKey) u32 {
        // TODO: Replace this entire thing with something sane
        const fkp = @ptrCast([*]const u32, @alignCast(4, fk));
        var lolhash: u32 = 0;
        var i: usize = 0;
        while (i < @sizeOf(FlowKey) / 4) : (i += 1) {
            lolhash ^= fkp[i];
        }
        return lolhash;
    }
    fn flowGet(self: Flowhandler, proto: u8, ip0: flowIP, ip1: flowIP, port0: u16, port1: u16) ?*Flow {
        const reverse = if ((ip0 > ip1) or (ip0 == ip1 and port0 > port1)) false else true;
        const ckey align(4) = FlowKey{
            .proto = proto,
            .ip0 = if (!reverse) ip0 else ip1,
            .ip1 = if (!reverse) ip1 else ip0,
            .port0 = if (!reverse) port0 else port1,
            .port1 = if (!reverse) port1 else port0,
            .pad = 0,
        };
        const hash = flowKeyHash(&ckey);
        const fmp = hash & (config.flows - 1);

        var i: usize = 0;
        while (i < config.flows) : (i += 1) {
            const fc = &self.flowmap[(fmp + i) & (config.flows - 1)];
            if (fc.hash == hash) {
                return fc;
            } else if (fc.occupied == 0) {
                fc.key = ckey;
                fc.hash = hash;
                fc.occupied = 1;
                if (reverse) {
                    fc.dir = 1;
                } else {
                    fc.dir = 0;
                }
                return fc;
            }
        }
        return null;
    }
    pub fn newPacket(self: Flowhandler, packet: []align(config.MTU) const u8) bool {
        if (packet.len < 28) // Size of empty IPv4 UDP packet
            return false;

        const eth = @ptrCast(*const ethernet, packet.ptr);

        if (config.IPv4 and eth.type == ethertype_ipv4) {
            return self.newPacketIPv4(packet[14..]);
        } else if (config.IPv6 and eth.type == ethertype_ipv6) {
            return self.newPacketIPv6(packet[14..]);
        } else {
            // TODO
            std.debug.warn("Unsupported ethertype {}\n", std.mem.bigToNative(u16, eth.type));
        }

        // return true if we keep a reference to it
        return false;
    }
    fn newPacketIPv4(self: Flowhandler, packet: []align(2) const u8) bool {
        const ip = @ptrCast(*const IPv4, packet.ptr);

        if (packet.len < u32(ip.IHL) * 4)
            return false;

        if (config.defragment_sw == false) {
            if (ip.flags != 0 and ip.flags != (1 << 6))
                return false;
        } else {
            // TODO... kinda fucks up the rx hash, needs special bucket for fragments... HMMMM
            // For now just drop
            if (ip.flags != 0 and ip.flags != (1 << 6))
                return false;
        }

        if (config.checksum_sw) {
            const tlength = std.mem.bigToNative(u16, ip.length);
            if (packet.len != tlength)
                return false;
            // CHECKSUM
        }

        if (ip.protocol == 1) {
            return newPacketIPv4ICMP(self, ip.src, ip.dst, packet[u32(ip.IHL) * 4 ..]);
        } else if (ip.protocol == 6) {
            return newPacketIPv4TCP(self, ip.src, ip.dst, packet[u32(ip.IHL) * 4 ..]);
        } else if (ip.protocol == 17) {
            return newPacketIPv4UDP(self, ip.src, ip.dst, packet[u32(ip.IHL) * 4 ..]);
        } else {
            // TODO
            std.debug.warn("Unsupported protocol {}\n", ip.protocol);
        }
        return false;
    }
    fn newPacketIPv6(self: Flowhandler, packet: []align(2) const u8) bool {
        // TODO
        return false;
    }
    fn newPacketIPv4ICMP(self: Flowhandler, src: u32, dst: u32, packet: []const u8) bool {
        // TODO
        return false;
    }
    fn newPacketIPv4TCP(self: Flowhandler, src: u32, dst: u32, packet: []const u8) bool {
        // TODO
        return false;
    }
    fn newPacketIPv4UDP(self: Flowhandler, src: u32, dst: u32, packet: []const u8) bool {
        if (packet.len < @sizeOf(UDP))
            return false;

        const udp = @ptrCast(*const UDP, packet.ptr);

        const flow = self.flowGet(1, src, dst, udp.src_port, udp.dst_port);
        if (flow) |fl| {
            // add packet to flow
        }
        return false;
    }
};
