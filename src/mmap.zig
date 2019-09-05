const std = @import("std");
pub usingnamespace std.os.linux;
pub usingnamespace @import("types.zig");
const kerror = @import("kerror.zig");
const config = @import("config.zig");

pub fn mmap_huge(size: usize, prot: usize, flags: u32) ![*]align(4096) u8 {
    var mmflags = flags;
    if (config.page_log2 == 0) {
        @compileError("A page size of 0 doesn't make sense");
    }
    if (config.page_log2 >= 16) {
        mmflags |= MAP_HUGETLB | (config.page_log2 << MAP_HUGE_SHIFT);
    }

    const _mem: usize = try kerror.toError(mmap(null, size, prot, mmflags, -1, 0));
    const mem = @intToPtr([*]align(4096) u8, _mem);
    errdefer _ = munmap(mem, size);

    // mmap can return success even if it failed to allocate hugepages (yes, even though we've got MAP_POPULATE) so we need to check manually
    const page_size = 1 << config.page_log2;
    const npages = ((size - 1) / page_size) + 1;
    if (config.page_log2 >= 16) {
        var i: usize = 0;
        while (i < npages) : (i += 1) {
            const memp = _mem + i * page_size;
            var mincore_flag: u8 = 0;
            _ = try kerror.toError(syscall3(SYS_mincore, memp, 1, @ptrToInt(&mincore_flag)));
            if (mincore_flag & 0x01 == 0) {
                return error.OutOfHugePages;
            }
        }
    }

    return mem;
}
