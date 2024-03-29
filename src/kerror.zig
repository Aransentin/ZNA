pub usingnamespace @import("std").os.linux;

pub fn toError(r: usize) !usize {
    var errno = getErrno(r);
    if (errno == 0) return r;

    return switch (errno) {
        0 => unreachable,
        1 => error.Errno1_EPERM,
        2 => error.Errno2_ENOENT,
        3 => error.Errno3_ESRCH,
        4 => error.Errno4_EINTR,
        5 => error.Errno5_EIO,
        6 => error.Errno6_ENXIO,
        7 => error.Errno7_E2BIG,
        8 => error.Errno8_ENOEXEC,
        9 => error.Errno9_EBADF,
        10 => error.Errno10_ECHILD,
        11 => error.Errno11_EAGAIN_or_EWOULDBLOCK,
        12 => error.Errno12_ENOMEM,
        13 => error.Errno13_EACCES,
        14 => error.Errno14_EFAULT,
        15 => error.Errno15_ENOTBLK,
        16 => error.Errno16_EBUSY,
        17 => error.Errno17_EEXIST,
        18 => error.Errno18_EXDEV,
        19 => error.Errno19_ENODEV,
        20 => error.Errno20_ENOTDIR,
        21 => error.Errno21_EISDIR,
        22 => error.Errno22_EINVAL,
        23 => error.Errno23_ENFILE,
        24 => error.Errno24_EMFILE,
        25 => error.Errno25_ENOTTY,
        26 => error.Errno26_ETXTBSY,
        27 => error.Errno27_EFBIG,
        28 => error.Errno28_ENOSPC,
        29 => error.Errno29_ESPIPE,
        30 => error.Errno30_EROFS,
        31 => error.Errno31_EMLINK,
        32 => error.Errno32_EPIPE,
        33 => error.Errno33_EDOM,
        34 => error.Errno34_ERANGE,
        35 => error.Errno35_EDEADLK,
        36 => error.Errno36_ENAMETOOLONG,
        37 => error.Errno37_ENOLCK,
        38 => error.Errno38_ENOSYS,
        39 => error.Errno39_ENOTEMPTY,
        40 => error.Errno40_ELOOP,
        41 => error.Errno41_Unknown,
        42 => error.Errno42_ENOMSG,
        43 => error.Errno43_EIDRM,
        44 => error.Errno44_ECHRNG,
        45 => error.Errno45_EL2NSYNC,
        46 => error.Errno46_EL3HLT,
        47 => error.Errno47_EL3RST,
        48 => error.Errno48_ELNRNG,
        49 => error.Errno49_EUNATCH,
        50 => error.Errno50_ENOCSI,
        51 => error.Errno51_EL2HLT,
        52 => error.Errno52_EBADE,
        53 => error.Errno53_EBADR,
        54 => error.Errno54_EXFULL,
        55 => error.Errno55_ENOANO,
        56 => error.Errno56_EBADRQC,
        57 => error.Errno57_EBADSLT,
        58 => error.Errno58_Unknown58,
        59 => error.Errno59_EBFONT,
        60 => error.Errno60_ENOSTR,
        61 => error.Errno61_ENODATA,
        62 => error.Errno62_ETIME,
        63 => error.Errno63_ENOSR,
        64 => error.Errno64_ENONET,
        65 => error.Errno65_ENOPKG,
        66 => error.Errno66_EREMOTE,
        67 => error.Errno67_ENOLINK,
        68 => error.Errno68_EADV,
        69 => error.Errno69_ESRMNT,
        70 => error.Errno70_ECOMM,
        71 => error.Errno71_EPROTO,
        72 => error.Errno72_EMULTIHOP,
        73 => error.Errno73_EDOTDOT,
        74 => error.Errno74_EBADMSG,
        75 => error.Errno75_EOVERFLOW,
        76 => error.Errno76_ENOTUNIQ,
        77 => error.Errno77_EBADFD,
        78 => error.Errno78_EREMCHG,
        79 => error.Errno79_ELIBACC,
        80 => error.Errno80_ELIBBAD,
        81 => error.Errno81_ELIBSCN,
        82 => error.Errno82_ELIBMAX,
        83 => error.Errno83_ELIBEXEC,
        84 => error.Errno84_EILSEQ,
        85 => error.Errno85_ERESTART,
        86 => error.Errno86_ESTRPIPE,
        87 => error.Errno87_EUSERS,
        88 => error.Errno88_ENOTSOCK,
        89 => error.Errno89_EDESTADDRREQ,
        90 => error.Errno90_EMSGSIZE,
        91 => error.Errno91_EPROTOTYPE,
        92 => error.Errno92_ENOPROTOOPT,
        93 => error.Errno93_EPROTONOSUPPORT,
        94 => error.Errno94_ESOCKTNOSUPPORT,
        95 => error.Errno95_EOPNOTSUPP,
        96 => error.Errno96_EPFNOSUPPORT,
        97 => error.Errno97_EAFNOSUPPORT,
        98 => error.Errno98_EADDRINUSE,
        99 => error.Errno99_EADDRNOTAVAIL,
        100 => error.Errno100_ENETDOWN,
        101 => error.Errno101_ENETUNREACH,
        102 => error.Errno102_ENETRESET,
        103 => error.Errno103_ECONNABORTED,
        104 => error.Errno104_ECONNRESET,
        105 => error.Errno105_ENOBUFS,
        106 => error.Errno106_EISCONN,
        107 => error.Errno107_ENOTCONN,
        108 => error.Errno108_ESHUTDOWN,
        109 => error.Errno109_ETOOMANYREFS,
        110 => error.Errno110_ETIMEDOUT,
        111 => error.Errno111_ECONNREFUSED,
        112 => error.Errno112_EHOSTDOWN,
        113 => error.Errno113_EHOSTUNREACH,
        114 => error.Errno114_EALREADY,
        115 => error.Errno115_EINPROGRESS,
        116 => error.Errno116_ESTALE,
        117 => error.Errno117_EUCLEAN,
        118 => error.Errno118_ENOTNAM,
        119 => error.Errno119_ENAVAIL,
        120 => error.Errno120_EISNAM,
        121 => error.Errno121_EREMOTEIO,
        122 => error.Errno122_EDQUOT,
        123 => error.Errno123_ENOMEDIUM,
        124 => error.Errno124_EMEDIUMTYPE,

        125 => error.Errno125_Unknown,
        126 => error.Errno126_Unknown,
        127 => error.Errno127_Unknown,
        128 => error.Errno128_Unknown,
        129 => error.Errno129_Unknown,
        130 => error.Errno130_Unknown,
        131 => error.Errno131_Unknown,
        132 => error.Errno132_Unknown,
        133 => error.Errno133_Unknown,
        134 => error.Errno134_Unknown,
        135 => error.Errno135_Unknown,
        136 => error.Errno136_Unknown,
        137 => error.Errno137_Unknown,
        138 => error.Errno138_Unknown,
        139 => error.Errno139_Unknown,
        140 => error.Errno140_Unknown,
        141 => error.Errno141_Unknown,
        142 => error.Errno142_Unknown,
        143 => error.Errno143_Unknown,
        144 => error.Errno144_Unknown,
        145 => error.Errno145_Unknown,
        146 => error.Errno146_Unknown,
        147 => error.Errno147_Unknown,
        148 => error.Errno148_Unknown,
        149 => error.Errno149_Unknown,
        150 => error.Errno150_Unknown,
        151 => error.Errno151_Unknown,
        152 => error.Errno152_Unknown,
        153 => error.Errno153_Unknown,
        154 => error.Errno154_Unknown,
        155 => error.Errno155_Unknown,
        156 => error.Errno156_Unknown,
        157 => error.Errno157_Unknown,
        158 => error.Errno158_Unknown,
        159 => error.Errno159_Unknown,

        160 => error.Errno160_ENSRNODATA,
        161 => error.Errno161_ENSRFORMERR,
        162 => error.Errno162_ENSRSERVFAIL,
        163 => error.Errno163_ENSRNOTFOUND,
        164 => error.Errno164_ENSRNOTIMP,
        165 => error.Errno165_ENSRREFUSED,
        166 => error.Errno166_ENSRBADQUERY,
        167 => error.Errno167_ENSRBADNAME,
        168 => error.Errno168_ENSRBADFAMILY,
        169 => error.Errno169_ENSRBADRESP,
        170 => error.Errno170_ENSRCONNREFUSED,
        171 => error.Errno171_ENSRTIMEOUT,
        172 => error.Errno172_ENSROF,
        173 => error.Errno173_ENSRFILE,
        174 => error.Errno174_ENSRNOMEM,
        175 => error.Errno175_ENSRDESTRUCTION,
        176 => error.Errno176_ENSRQUERYDOMAINTOOLONG,
        177 => error.Errno177_ENSRCNAMELOOP,

        else => error.Errno_GT_177_Unknown,
    };
}
