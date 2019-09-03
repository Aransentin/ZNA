// IPS mode (send packets onwards to second interface)
pub const IPS = false;

// Name of the interface to capture packets from
//pub const if_cap_name = "enp4s0";
pub const if_cap_name = "lo";

// Name of the interface to send analyzed packets to. Has no effect unless 'IPS' is set to true.
pub const if_out_name = "";

// An array of worker CPU cores. Must not exceed the number of queues of the capture interface.
pub const workers = [_]u32{3};

// Specify memory page size in 2^page_size (e.g. 21 for 2MiB hugepages) 12 will get you the regular 4KiB page size.
// Anything lower that 16 (i.e. 64KiB pages) will disable hugepages entirely.
// TODO: echo X > /proc/sys/vm/nr_hugepages
pub const page_log2 = 21;

// Specify the maximum packet size. XDP requires this to be a power of 2 and at least 2048,
// so that is the sane choice unless you're working with jumbo frames or the like.
pub const MTU = 2048;

// Size of the per-worker packet buffer in MTU-sized packets. Must be a power of 2.
pub const npackets = 2048;

// How long the kernel should busy poll for packets (in μs), or 0 for disabling SO_BUSY_POLL entirely.
// Busy polling may improve performance by an order of magnitude for loaded systems, but just increases CPU consumption otherwise.
pub const busy_poll: usize = 10 * 1000;

// Maximum number of flows tracked.
pub const flows: usize = 4096;

// How accurately to measure flow timestamps
// 0 -> No timestamps
// 1 -> Nearest 100 milliseconds
// 2 -> Nearest ? milliseconds
// 3 -> unique timestamp for each flow as accurately as we can get
pub const time_accuracy: usize = 0;

// How deep a flow should be parsed before being becoming a candidate for pruning.
pub const flow_size: usize = 1024 * 256;

// How many milliseconds old a flow will get before becoming a candidate for pruning.
pub const flow_timeout_age: usize = 1000 * 60;

// How many milliseconds since the last packet for a flow to become a candidate for pruning.
pub const flow_timeout_stale: usize = 1000 * 10;

// Enable seccomp, ensuring that only specific syscalls/fd combinations may be executed.
// This improves security for a (slight) cost in performance and potentially exposing bugs.
// NOT IMPLEMENTED
pub const seccomp = false;

// Use the port number in the packet-to-queue calculation, improving load balance
// between threads. Not compatible with packet defragmentation as pieces may end up
// on different workers, so requires either hardware defragmentation or limiting the
// workers to one.
pub const rx_hash_port = true;

// Enable decoding of IPv4 packets.
pub const IPv4 = true;

// Enable decoding of IPv6 packets.
pub const IPv6 = true;

// Defragment packets in hardware.
pub const defragment_hw = true;

// Defragment packets in software.
pub const defragment_sw = false;

// Verify packet checksums in hardware
pub const checksum_hw = true;

// Verify packet checksums in software
pub const checksum_sw = true;

// vlan etc...
