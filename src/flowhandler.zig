const std = @import("std");
const config = @import("config.zig");

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
    src: [4]u8,
    dst: [4]u8,
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

fn packetAddrsIsIPv6(ip: [*]const u8) bool {
    if (!config.IPv6) {
        return false;
    }
    if (!config.IPv4) {
        return true;
    }
    const ipv6_src_offset = 14 + 4 * 2;
    if (@ptrToInt(ip - ipv6_src_offset) & 1023 == 0) {
        return true;
    } else {
        return false;
    }
}

const FlowData = struct {
    dir: u1,
    pad: u7,
    pages: u8,
};

const Flow = struct {
    type: u8,
    pad: u8,
    ip0: if (config.IPv6) [16]u8 else [4]u8,
    ip1: if (config.IPv6) [16]u8 else [4]u8,
    port0: u16,
    port1: u16,
    data: [*]u8,
};

pub const Flowhandler = struct {
    flowmap: [*]align(4096) u8,

    pub fn init(self: *Flowhandler) anyerror!void {
        // mmap flowmap
        // [5-tuple (+2)] -> *ptr
    }
    pub fn deinit(self: *Flowhandler) void {
        // munmap flowmap
    }
    pub fn newPacket(self: Flowhandler, packet: []align(config.MTU) const u8) bool {
        if (packet.len < 28) // Empty IPv4 UDP packet
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
            if (ip.protocol != 17) {
                // Only defrag UDP
                return false;
            }
            // TODO... kinda fucks up the rx hash, needs special bucket for fragments... HMMMM
        }

        if (config.checksum_sw) {
            const tlength = std.mem.bigToNative(u16, ip.length);
            if (packet.len != tlength)
                return false;
        }

        if (ip.protocol == 6) {
            return newPacketTCP(self, &ip.src, packet[u32(ip.IHL) * 4 ..]);
        } else if (ip.protocol == 17) {
            return newPacketUDP(self, &ip.src, packet[u32(ip.IHL) * 4 ..]);
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
    fn newPacketTCP(self: Flowhandler, addrs: [*]const u8, packet: []const u8) bool {
        // TODO
        std.debug.warn("TCP\n");
        return false;
    }
    fn newPacketUDP(self: Flowhandler, addrs: [*]const u8, packet: []const u8) bool {
        if (packet.len < @sizeOf(UDP))
            return false;

        const udp = @ptrCast(*const UDP, packet.ptr);

        // Find in UDP flowlist hash table...
        // ...

        // std.debug.warn("UDP: {}->{}\n", std.mem.bigToNative(u16, udp.src_port), std.mem.bigToNative(u16, udp.dst_port));

        return false;
    }
};
