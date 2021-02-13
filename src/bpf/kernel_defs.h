// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#ifndef KERNEL_DEFS_H
#define KERNEL_DEFS_H

#include "vmlinux.h"

/* ========================================================================= *
 * /uapi/asm-generic/errno-base.h                                            *
 * ========================================================================= */

/* Error numbers
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/asm-generic/errno-base.h#L5
 */
#define EPERM   1  /* Operation not permitted */
#define ENOENT  2  /* No such file or directory */
#define ESRCH   3  /* No such process */
#define EINTR   4  /* Interrupted system call */
#define EIO     5  /* I/O error */
#define ENXIO   6  /* No such device or address */
#define E2BIG   7  /* Argument list too long */
#define ENOEXEC 8  /* Exec format error */
#define EBADF   9  /* Bad file number */
#define ECHILD  10 /* No child processes */
#define EAGAIN  11 /* Try again */
#define ENOMEM  12 /* Out of memory */
#define EACCES  13 /* Permission denied */
#define EFAULT  14 /* Bad address */
#define ENOTBLK 15 /* Block device required */
#define EBUSY   16 /* Device or resource busy */
#define EEXIST  17 /* File exists */
#define EXDEV   18 /* Cross-device link */
#define ENODEV  19 /* No such device */
#define ENOTDIR 20 /* Not a directory */
#define EISDIR  21 /* Is a directory */
#define EINVAL  22 /* Invalid argument */
#define ENFILE  23 /* File table overflow */
#define EMFILE  24 /* Too many open files */
#define ENOTTY  25 /* Not a typewriter */
#define ETXTBSY 26 /* Text file busy */
#define EFBIG   27 /* File too large */
#define ENOSPC  28 /* No space left on device */
#define ESPIPE  29 /* Illegal seek */
#define EROFS   30 /* Read-only file system */
#define EMLINK  31 /* Too many links */
#define EPIPE   32 /* Broken pipe */
#define EDOM    33 /* Math argument out of domain of func */
#define ERANGE  34 /* Math result not representable */

#define EDEADLK      35 /* Resource deadlock would occur */
#define ENAMETOOLONG 36 /* File name too long */
#define ENOLCK       37 /* No record locks available */

/*
 * This error code is special: arch syscall entry code will return
 * -ENOSYS if users try to call a syscall that doesn't exist.  To keep
 * failures of syscalls that really do exist distinguishable from
 * failures due to attempts to use a nonexistent syscall, syscall
 * implementations should refrain from returning -ENOSYS.
 */
#define ENOSYS 38 /* Invalid system call number */

#define ENOTEMPTY   39     /* Directory not empty */
#define ELOOP       40     /* Too many symbolic links encountered */
#define EWOULDBLOCK EAGAIN /* Operation would block */
#define ENOMSG      42     /* No message of desired type */
#define EIDRM       43     /* Identifier removed */
#define ECHRNG      44     /* Channel number out of range */
#define EL2NSYNC    45     /* Level 2 not synchronized */
#define EL3HLT      46     /* Level 3 halted */
#define EL3RST      47     /* Level 3 reset */
#define ELNRNG      48     /* Link number out of range */
#define EUNATCH     49     /* Protocol driver not attached */
#define ENOCSI      50     /* No CSI structure available */
#define EL2HLT      51     /* Level 2 halted */
#define EBADE       52     /* Invalid exchange */
#define EBADR       53     /* Invalid request descriptor */
#define EXFULL      54     /* Exchange full */
#define ENOANO      55     /* No anode */
#define EBADRQC     56     /* Invalid request code */
#define EBADSLT     57     /* Invalid slot */

#define EDEADLOCK EDEADLK

#define EBFONT          59 /* Bad font file format */
#define ENOSTR          60 /* Device not a stream */
#define ENODATA         61 /* No data available */
#define ETIME           62 /* Timer expired */
#define ENOSR           63 /* Out of streams resources */
#define ENONET          64 /* Machine is not on the network */
#define ENOPKG          65 /* Package not installed */
#define EREMOTE         66 /* Object is remote */
#define ENOLINK         67 /* Link has been severed */
#define EADV            68 /* Advertise error */
#define ESRMNT          69 /* Srmount error */
#define ECOMM           70 /* Communication error on send */
#define EPROTO          71 /* Protocol error */
#define EMULTIHOP       72 /* Multihop attempted */
#define EDOTDOT         73 /* RFS specific error */
#define EBADMSG         74 /* Not a data message */
#define EOVERFLOW       75 /* Value too large for defined data type */
#define ENOTUNIQ        76 /* Name not unique on network */
#define EBADFD          77 /* File descriptor in bad state */
#define EREMCHG         78 /* Remote address changed */
#define ELIBACC         79 /* Can not access a needed shared library */
#define ELIBBAD         80 /* Accessing a corrupted shared library */
#define ELIBSCN         81 /* .lib section in a.out corrupted */
#define ELIBMAX         82 /* Attempting to link in too many shared libraries */
#define ELIBEXEC        83 /* Cannot exec a shared library directly */
#define EILSEQ          84 /* Illegal byte sequence */
#define ERESTART        85 /* Interrupted system call should be restarted */
#define ESTRPIPE        86 /* Streams pipe error */
#define EUSERS          87 /* Too many users */
#define ENOTSOCK        88 /* Socket operation on non-socket */
#define EDESTADDRREQ    89 /* Destination address required */
#define EMSGSIZE        90 /* Message too long */
#define EPROTOTYPE      91 /* Protocol wrong type for socket */
#define ENOPROTOOPT     92 /* Protocol not available */
#define EPROTONOSUPPORT 93 /* Protocol not supported */
#define ESOCKTNOSUPPORT 94 /* Socket type not supported */
#define EOPNOTSUPP      95 /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT    96 /* Protocol family not supported */
#define EAFNOSUPPORT    97 /* Address family not supported by protocol */
#define EADDRINUSE      98 /* Address already in use */
#define EADDRNOTAVAIL   99 /* Cannot assign requested address */
#define ENETDOWN        100 /* Network is down */
#define ENETUNREACH     101 /* Network is unreachable */
#define ENETRESET       102 /* Network dropped connection because of reset */
#define ECONNABORTED    103 /* Software caused connection abort */
#define ECONNRESET      104 /* Connection reset by peer */
#define ENOBUFS         105 /* No buffer space available */
#define EISCONN         106 /* Transport endpoint is already connected */
#define ENOTCONN        107 /* Transport endpoint is not connected */
#define ESHUTDOWN       108 /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS    109 /* Too many references: cannot splice */
#define ETIMEDOUT       110 /* Connection timed out */
#define ECONNREFUSED    111 /* Connection refused */
#define EHOSTDOWN       112 /* Host is down */
#define EHOSTUNREACH    113 /* No route to host */
#define EALREADY        114 /* Operation already in progress */
#define EINPROGRESS     115 /* Operation now in progress */
#define ESTALE          116 /* Stale file handle */
#define EUCLEAN         117 /* Structure needs cleaning */
#define ENOTNAM         118 /* Not a XENIX named type file */
#define ENAVAIL         119 /* No XENIX semaphores available */
#define EISNAM          120 /* Is a named type file */
#define EREMOTEIO       121 /* Remote I/O error */
#define EDQUOT          122 /* Quota exceeded */

#define ENOMEDIUM    123 /* No medium found */
#define EMEDIUMTYPE  124 /* Wrong medium type */
#define ECANCELED    125 /* Operation Canceled */
#define ENOKEY       126 /* Required key not available */
#define EKEYEXPIRED  127 /* Key has expired */
#define EKEYREVOKED  128 /* Key has been revoked */
#define EKEYREJECTED 129 /* Key was rejected by service */

/* for robust mutexes */
#define EOWNERDEAD      130 /* Owner died */
#define ENOTRECOVERABLE 131 /* State not recoverable */

#define ERFKILL 132 /* Operation not possible due to RF-kill */

#define EHWPOISON 133 /* Memory page has hardware error */

/* ========================================================================= *
 * linux/fs.h                                                                *
 * ========================================================================= */

/* File permissions
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/fs.h#L95 */
#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN   0x00000020
#define MAY_CHDIR  0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK 0x00000080

/* file is open for reading */
#define FMODE_READ 0x1
/* file is open for writing */
#define FMODE_WRITE 0x2
/* file is seekable */
#define FMODE_LSEEK 0x4
/* file can be accessed using pread */
#define FMODE_PREAD 0x8
/* file can be accessed using pwrite */
#define FMODE_PWRITE 0x10
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC 0x20
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY 0x40
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL 0x80
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL 0x100
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH 0x200
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH 0x400

/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME 0x800

/* Expect random access pattern */
#define FMODE_RANDOM 0x1000

/* File is huge (eg. /dev/kmem): treat loff_t as unsigned */
#define FMODE_UNSIGNED_OFFSET 0x2000

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH 0x4000

/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS 0x8000
/* Write access to underlying fs */
#define FMODE_WRITER 0x10000
/* Has read method(s) */
#define FMODE_CAN_READ 0x20000
/* Has write method(s) */
#define FMODE_CAN_WRITE 0x40000

#define FMODE_OPENED  0x80000
#define FMODE_CREATED 0x100000

/* File is stream-like */
#define FMODE_STREAM 0x200000

/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY 0x4000000

/* File is capable of returning -EAGAIN if I/O will block */
#define FMODE_NOWAIT 0x8000000

/* File represents mount that needs unmounting */
#define FMODE_NEED_UNMOUNT 0x10000000

/* File does not contribute to nr_files count */
#define FMODE_NOACCOUNT 0x20000000

/* File supports async buffered reads */
#define FMODE_BUF_RASYNC 0x40000000

/* sb flags
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/fs.h#L1345 */
#define SB_RDONLY      1    /* Mount read-only */
#define SB_NOSUID      2    /* Ignore suid and sgid bits */
#define SB_NODEV       4    /* Disallow access to device special files */
#define SB_NOEXEC      8    /* Disallow program execution */
#define SB_SYNCHRONOUS 16   /* Writes are synced at once */
#define SB_MANDLOCK    64   /* Allow mandatory locks on an FS */
#define SB_DIRSYNC     128  /* Directory modifications are synchronous */
#define SB_NOATIME     1024 /* Do not update access times. */
#define SB_NODIRATIME  2048 /* Do not update directory access times */
#define SB_SILENT      32768
#define SB_POSIXACL    (1 << 16) /* VFS does not apply the umask */
#define SB_INLINECRYPT (1 << 17) /* Use blk-crypto for encrypted files */
#define SB_KERNMOUNT   (1 << 22) /* this is a kern_mount call */
#define SB_I_VERSION   (1 << 23) /* Update inode I_version field */
#define SB_LAZYTIME    (1 << 25) /* Update the on-disk [acm]times lazily */
/* These sb flags are internal to the kernel */
#define SB_SUBMOUNT (1 << 26)
#define SB_FORCE    (1 << 27)
#define SB_NOSEC    (1 << 28)
#define SB_BORN     (1 << 29)
#define SB_ACTIVE   (1 << 30)
#define SB_NOUSER   (1 << 31)

/* ========================================================================= *
 * uapi/asm-generic/fcntl.h                                                  *
 * ========================================================================= */

#define O_ACCMODE 00000003
#define O_RDONLY  00000000
#define O_WRONLY  00000001
#define O_RDWR    00000002
#ifndef O_CREAT
#define O_CREAT 00000100 /* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL 00000200 /* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 00000400 /* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000 /* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC 00010000 /* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC 00020000 /* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT 00040000 /* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000 /* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 00400000 /* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000 /* set close_on_exec */
#endif

/* ========================================================================= *
 * linux/stat.h                                                              *
 * ========================================================================= */

/* stat flags and macros
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/stat.h#L9 */
#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

/* ========================================================================= *
 * linux/kdev_t.h                                                            *
 * ========================================================================= */

/* Device ID macros
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/kdev_t.h#L7 */
#define MINORBITS     20
#define MINORMASK     ((1U << MINORBITS) - 1)
#define MAJOR(dev)    ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int)((dev)&MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

/* Encode a device ID
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/kdev_t.h#L39 */
static inline u32 new_encode_dev(dev_t dev)
{
    unsigned major = MAJOR(dev);
    unsigned minor = MINOR(dev);
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

/* ========================================================================= *
 * uapi/asm-generic/mman-common.h                                            *
 * ========================================================================= */

/* mmap prot
 * https://elixir.bootlin.com/linux/v6.10/source/include/uapi/asm-generic/mman-common.h#L10
 */
#define PROT_READ  0x1 /* page can be read */
#define PROT_WRITE 0x2 /* page can be written */
#define PROT_EXEC  0x4 /* page can be executed */

/* ========================================================================= *
 * uapi/linux/mman.h                                                         *
 * ========================================================================= */

/* mmap flags
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/mman.h#L8 */
#define MREMAP_MAYMOVE   1
#define MREMAP_FIXED     2
#define MREMAP_DONTUNMAP 4

#define OVERCOMMIT_GUESS  0
#define OVERCOMMIT_ALWAYS 1
#define OVERCOMMIT_NEVER  2

#define MAP_SHARED          0x01 /* Share changes */
#define MAP_PRIVATE         0x02 /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */

/* ========================================================================= *
 * uapi/linux/mman.h                                                         *
 * ========================================================================= */

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/mm.h#L253
 */
#define VM_NONE 0x00000000

#define VM_READ   0x00000001 /* currently active flags */
#define VM_WRITE  0x00000002
#define VM_EXEC   0x00000004
#define VM_SHARED 0x00000008

/* ========================================================================= *
 * linux/socket.h                                                            *
 * ========================================================================= */

/* Supported address families.
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/socket.h#L175 */
#define AF_UNSPEC     0
#define AF_UNIX       1 /* Unix domain sockets            */
#define AF_LOCAL      1 /* POSIX name for AF_UNIX         */
#define AF_INET       2 /* Internet IP Protocol           */
#define AF_AX25       3 /* Amateur Radio AX.25            */
#define AF_IPX        4 /* Novell IPX                     */
#define AF_APPLETALK  5 /* AppleTalk DDP              */
#define AF_NETROM     6 /* Amateur Radio NET/ROM          */
#define AF_BRIDGE     7 /* Multiprotocol bridge           */
#define AF_ATMPVC     8 /* ATM PVCs                       */
#define AF_X25        9 /* Reserved for X.25 project      */
#define AF_INET6      10 /* IP version 6                   */
#define AF_ROSE       11 /* Amateur Radio X.25 PLP         */
#define AF_DECnet     12 /* Reserved for DECnet project    */
#define AF_NETBEUI    13 /* Reserved for 802.2LLC project  */
#define AF_SECURITY   14 /* Security callback pseudo AF    */
#define AF_KEY        15 /* PF_KEY key management API      */
#define AF_NETLINK    16
#define AF_ROUTE      AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET     17 /* Packet family                  */
#define AF_ASH        18 /* Ash                            */
#define AF_ECONET     19 /* Acorn Econet                   */
#define AF_ATMSVC     20 /* ATM SVCs                       */
#define AF_RDS        21 /* RDS sockets                    */
#define AF_SNA        22 /* Linux SNA Project (nutters!)   */
#define AF_IRDA       23 /* IRDA sockets                   */
#define AF_PPPOX      24 /* PPPoX sockets                  */
#define AF_WANPIPE    25 /* Wanpipe API Sockets            */
#define AF_LLC        26 /* Linux LLC                      */
#define AF_IB         27 /* Native InfiniBand address      */
#define AF_MPLS       28 /* MPLS                           */
#define AF_CAN        29 /* Controller Area Network        */
#define AF_TIPC       30 /* TIPC sockets                   */
#define AF_BLUETOOTH  31 /* Bluetooth sockets             */
#define AF_IUCV       32 /* IUCV sockets                   */
#define AF_RXRPC      33 /* RxRPC sockets                  */
#define AF_ISDN       34 /* mISDN sockets                  */
#define AF_PHONET     35 /* Phonet sockets                 */
#define AF_IEEE802154 36 /* IEEE802154 sockets           */
#define AF_CAIF       37 /* CAIF sockets                   */
#define AF_ALG        38 /* Algorithm sockets              */
#define AF_NFC        39 /* NFC sockets                    */
#define AF_VSOCK      40 /* vSockets                       */
#define AF_KCM        41 /* Kernel Connection Multiplexor  */
#define AF_QIPCRTR    42 /* Qualcomm IPC Router            */
#define AF_SMC                            \
    43 /* smc sockets: reserve number for \
        * PF_SMC protocol family that     \
        * reuses AF_INET address family   \
        */
#define AF_XDP 44 /* XDP sockets          */

#define AF_MAX 45 /* For now.. */

/* ========================================================================= *
 * arch/x86/include/uapi/asm/signal.h                                        *
 * ========================================================================= */

/* Signal numbers TODO: handle other archs
 * https://elixir.bootlin.com/linux/v5.10/source/arch/x86/include/uapi/asm/signal.h#L23
 */
#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    6
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   SIGIO
#define SIGLOST   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED 31

/* ========================================================================= *
 * uapi/linux/capability.h                                                   *
 * ========================================================================= */

/* POSIX capabilities
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/capability.h#L105
 */
#define CAP_CHOWN              0
#define CAP_DAC_OVERRIDE       1
#define CAP_DAC_READ_SEARCH    2
#define CAP_FOWNER             3
#define CAP_FSETID             4
#define CAP_KILL               5
#define CAP_SETGID             6
#define CAP_SETUID             7
#define CAP_SETPCAP            8
#define CAP_LINUX_IMMUTABLE    9
#define CAP_NET_BIND_SERVICE   10
#define CAP_NET_BROADCAST      11
#define CAP_NET_ADMIN          12
#define CAP_NET_RAW            13
#define CAP_IPC_LOCK           14
#define CAP_IPC_OWNER          15
#define CAP_SYS_MODULE         16
#define CAP_SYS_RAWIO          17
#define CAP_SYS_CHROOT         18
#define CAP_SYS_PTRACE         19
#define CAP_SYS_PACCT          20
#define CAP_SYS_ADMIN          21
#define CAP_SYS_BOOT           22
#define CAP_SYS_NICE           23
#define CAP_SYS_RESOURCE       24
#define CAP_SYS_TIME           25
#define CAP_SYS_TTY_CONFIG     26
#define CAP_MKNOD              27
#define CAP_LEASE              28
#define CAP_AUDIT_WRITE        29
#define CAP_AUDIT_CONTROL      30
#define CAP_SETFCAP            31
#define CAP_MAC_OVERRIDE       32
#define CAP_MAC_ADMIN          33
#define CAP_SYSLOG             34
#define CAP_WAKE_ALARM         35
#define CAP_BLOCK_SUSPEND      36
#define CAP_AUDIT_READ         37
#define CAP_PERFMON            38
#define CAP_BPF                39
#define CAP_CHECKPOINT_RESTORE 40

#define CAP_LAST_CAP CAP_CHECKPOINT_RESTORE

/* ========================================================================= *
 * uapi/linux/capability.h                                                   *
 * ========================================================================= */

/*
 * These are the fs-independent mount-flags: up to 32 flags are supported
 *
 * Usage of these is restricted within the kernel to core mount(2) code and
 * callers of sys_mount() only.  Filesystems should be using the SB_*
 * equivalent instead.
 */
#define MS_RDONLY      1 /* Mount read-only */
#define MS_NOSUID      2 /* Ignore suid and sgid bits */
#define MS_NODEV       4 /* Disallow access to device special files */
#define MS_NOEXEC      8 /* Disallow program execution */
#define MS_SYNCHRONOUS 16 /* Writes are synced at once */
#define MS_REMOUNT     32 /* Alter flags of a mounted FS */
#define MS_MANDLOCK    64 /* Allow mandatory locks on an FS */
#define MS_DIRSYNC     128 /* Directory modifications are synchronous */
#define MS_NOSYMFOLLOW 256 /* Do not follow symlinks */
#define MS_NOATIME     1024 /* Do not update access times. */
#define MS_NODIRATIME  2048 /* Do not update directory access times */
#define MS_BIND        4096
#define MS_MOVE        8192
#define MS_REC         16384
#define MS_VERBOSE     32768
#define MS_SILENT      32768
#define MS_POSIXACL    (1 << 16) /* VFS does not apply the umask */
#define MS_UNBINDABLE  (1 << 17) /* change to unbindable */
#define MS_PRIVATE     (1 << 18) /* change to private */
#define MS_SLAVE       (1 << 19) /* change to slave */
#define MS_SHARED      (1 << 20) /* change to shared */
#define MS_RELATIME    (1 << 21) /* Update atime relative to mtime/ctime. */
#define MS_KERNMOUNT   (1 << 22) /* this is a kern_mount call */
#define MS_I_VERSION   (1 << 23) /* Update inode I_version field */
#define MS_STRICTATIME (1 << 24) /* Always perform atime updates */
#define MS_LAZYTIME    (1 << 25) /* Update the on-disk [acm]times lazily */

/* These sb flags are internal to the kernel */
#define MS_SUBMOUNT     (1 << 26)
#define MS_NOREMOTELOCK (1 << 27)
#define MS_NOSEC        (1 << 28)
#define MS_BORN         (1 << 29)
#define MS_ACTIVE       (1 << 30)
#define MS_NOUSER       (1 << 31)

/*
 * Superblock flags that can be altered by MS_REMOUNT
 */
#define MS_RMT_MASK \
    (MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME)

/*
 * Old magic mount flag and mask
 */
#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

/*
 * open_tree() flags.
 */
#define OPEN_TREE_CLONE   1 /* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC O_CLOEXEC /* Close the file on execve() */

/*
 * move_mount() flags.
 */
#define MOVE_MOUNT_F_SYMLINKS 0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS                  \
    0x00000002 /* Follow automounts on from path \
                */
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS   0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#define MOVE_MOUNT__MASK        0x00000077

/*
 * fsopen() flags.
 */
#define FSOPEN_CLOEXEC 0x00000001

/*
 * fspick() flags.
 */
#define FSPICK_CLOEXEC          0x00000001
#define FSPICK_SYMLINK_NOFOLLOW 0x00000002
#define FSPICK_NO_AUTOMOUNT     0x00000004
#define FSPICK_EMPTY_PATH       0x00000008

/*
 * fsmount() flags.
 */
#define FSMOUNT_CLOEXEC 0x00000001

/*
 * Mount attributes.
 */
#define MOUNT_ATTR_RDONLY 0x00000001 /* Mount read-only */
#define MOUNT_ATTR_NOSUID 0x00000002 /* Ignore suid and sgid bits */
/* Disallow access to device special files */
#define MOUNT_ATTR_NODEV 0x00000004
/* Disallow program execution */
#define MOUNT_ATTR_NOEXEC 0x00000008
/* Setting on how atime should be updated */
#define MOUNT_ATTR__ATIME 0x00000070
/* Update atime relative to mtime/ctime. */
#define MOUNT_ATTR_RELATIME    0x00000000
#define MOUNT_ATTR_NOATIME     0x00000010 /* Do not update access times. */
#define MOUNT_ATTR_STRICTATIME 0x00000020 /* Always perform atime updates */
#define MOUNT_ATTR_NODIRATIME  0x00000080
/* Do not update directory access times */

/* ========================================================================= *
 * linux/fs.h                                                                *
 * ========================================================================= */

/*
 * sb->s_flags.  Note that these mirror the equivalent MS_* flags where
 * represented in both.
 */
#define SB_RDONLY      1 /* Mount read-only */
#define SB_NOSUID      2 /* Ignore suid and sgid bits */
#define SB_NODEV       4 /* Disallow access to device special files */
#define SB_NOEXEC      8 /* Disallow program execution */
#define SB_SYNCHRONOUS 16 /* Writes are synced at once */
#define SB_MANDLOCK    64 /* Allow mandatory locks on an FS */
#define SB_DIRSYNC     128 /* Directory modifications are synchronous */
#define SB_NOATIME     1024 /* Do not update access times. */
#define SB_NODIRATIME  2048 /* Do not update directory access times */
#define SB_SILENT      32768
#define SB_POSIXACL    (1 << 16) /* VFS does not apply the umask */
#define SB_INLINECRYPT (1 << 17) /* Use blk-crypto for encrypted files */
#define SB_KERNMOUNT   (1 << 22) /* this is a kern_mount call */
#define SB_I_VERSION   (1 << 23) /* Update inode I_version field */
#define SB_LAZYTIME    (1 << 25) /* Update the on-disk [acm]times lazily */

/* These sb flags are internal to the kernel */
#define SB_SUBMOUNT (1 << 26)
#define SB_FORCE    (1 << 27)
#define SB_NOSEC    (1 << 28)
#define SB_BORN     (1 << 29)
#define SB_ACTIVE   (1 << 30)
#define SB_NOUSER   (1 << 31)

/* sb->s_iflags */
#define SB_I_CGROUPWB  0x00000001 /* cgroup-aware writeback enabled */
#define SB_I_NOEXEC    0x00000002 /* Ignore executables on this fs */
#define SB_I_NODEV     0x00000004 /* Ignore devices on this fs */
#define SB_I_MULTIROOT 0x00000008 /* Multiple roots to the dentry tree */

/* sb->s_iflags to limit user namespace mounts */
#define SB_I_USERNS_VISIBLE             0x00000010 /* fstype already mounted */
#define SB_I_IMA_UNVERIFIABLE_SIGNATURE 0x00000020
#define SB_I_UNTRUSTED_MOUNTER          0x00000040

#define SB_I_SKIP_SYNC 0x00000100 /* Skip superblock at global sync */

/* ========================================================================= *
 * include/uapi/linux/magic.h                                                *
 * ========================================================================= */

#define ADFS_SUPER_MAGIC   0xadf5
#define AFFS_SUPER_MAGIC   0xadff
#define AFS_SUPER_MAGIC    0x5346414F
#define AUTOFS_SUPER_MAGIC 0x0187
#define CODA_SUPER_MAGIC   0x73757245
#define CRAMFS_MAGIC       0x28cd3d45 /* some random number */
/* magic number with the wrong endianess */
#define CRAMFS_MAGIC_WEND     0x453dcd28
#define DEBUGFS_MAGIC         0x64626720
#define SECURITYFS_MAGIC      0x73636673
#define SELINUX_MAGIC         0xf97cff8c
#define SMACK_MAGIC           0x43415d53 /* "SMAC" */
#define RAMFS_MAGIC           0x858458f6 /* some random number */
#define TMPFS_MAGIC           0x01021994
#define HUGETLBFS_MAGIC       0x958458f6 /* some random number */
#define SQUASHFS_MAGIC        0x73717368
#define ECRYPTFS_SUPER_MAGIC  0xf15f
#define EFS_SUPER_MAGIC       0x414A53
#define EROFS_SUPER_MAGIC_V1  0xE0F5E1E2
#define EXT2_SUPER_MAGIC      0xEF53
#define EXT3_SUPER_MAGIC      0xEF53
#define XENFS_SUPER_MAGIC     0xabba1974
#define EXT4_SUPER_MAGIC      0xEF53
#define BTRFS_SUPER_MAGIC     0x9123683E
#define NILFS_SUPER_MAGIC     0x3434
#define F2FS_SUPER_MAGIC      0xF2F52010
#define HPFS_SUPER_MAGIC      0xf995e849
#define ISOFS_SUPER_MAGIC     0x9660
#define JFFS2_SUPER_MAGIC     0x72b6
#define XFS_SUPER_MAGIC       0x58465342 /* "XFSB" */
#define PSTOREFS_MAGIC        0x6165676C
#define EFIVARFS_MAGIC        0xde5e81e4
#define HOSTFS_SUPER_MAGIC    0x00c0ffee
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

#define MINIX_SUPER_MAGIC   0x137F /* minix v1 fs, 14 char names */
#define MINIX_SUPER_MAGIC2  0x138F /* minix v1 fs, 30 char names */
#define MINIX2_SUPER_MAGIC  0x2468 /* minix v2 fs, 14 char names */
#define MINIX2_SUPER_MAGIC2 0x2478 /* minix v2 fs, 30 char names */
#define MINIX3_SUPER_MAGIC  0x4d5a /* minix v3 fs, 60 char names */

#define MSDOS_SUPER_MAGIC    0x4d44 /* MD */
#define NCP_SUPER_MAGIC      0x564c /* Guess, what 0x564c is :-) */
#define NFS_SUPER_MAGIC      0x6969
#define OCFS2_SUPER_MAGIC    0x7461636f
#define OPENPROM_SUPER_MAGIC 0x9fa1
#define QNX4_SUPER_MAGIC     0x002f /* qnx4 fs detection */
#define QNX6_SUPER_MAGIC     0x68191122 /* qnx6 fs detection */
#define AFS_FS_MAGIC         0x6B414653

#define REISERFS_SUPER_MAGIC 0x52654973 /* used by gcc */
/* used by file system utilities that
   look at the superblock, etc.  */
#define REISERFS_SUPER_MAGIC_STRING     "ReIsErFs"
#define REISER2FS_SUPER_MAGIC_STRING    "ReIsEr2Fs"
#define REISER2FS_JR_SUPER_MAGIC_STRING "ReIsEr3Fs"

#define SMB_SUPER_MAGIC     0x517B
#define CGROUP_SUPER_MAGIC  0x27e0eb
#define CGROUP2_SUPER_MAGIC 0x63677270

#define RDTGROUP_SUPER_MAGIC 0x7655821

#define STACK_END_MAGIC 0x57AC6E9D

#define TRACEFS_MAGIC 0x74726163

#define V9FS_MAGIC 0x01021997

#define BDEVFS_MAGIC          0x62646576
#define DAXFS_MAGIC           0x64646178
#define BINFMTFS_MAGIC        0x42494e4d
#define DEVPTS_SUPER_MAGIC    0x1cd1
#define BINDERFS_SUPER_MAGIC  0x6c6f6f70
#define FUTEXFS_SUPER_MAGIC   0xBAD1DEA
#define PIPEFS_MAGIC          0x50495045
#define PROC_SUPER_MAGIC      0x9fa0
#define SOCKFS_MAGIC          0x534F434B
#define SYSFS_MAGIC           0x62656572
#define USBDEVICE_SUPER_MAGIC 0x9fa2
#define MTD_INODE_FS_MAGIC    0x11307854
#define ANON_INODE_FS_MAGIC   0x09041934
#define BTRFS_TEST_MAGIC      0x73727279
#define NSFS_MAGIC            0x6e736673
#define BPF_FS_MAGIC          0xcafe4a11
#define AAFS_MAGIC            0x5a3c69f0
#define ZONEFS_MAGIC          0x5a4f4653

/* Since UDF 2.01 is ISO 13346 based... */
#define UDF_SUPER_MAGIC   0x15013346
#define BALLOON_KVM_MAGIC 0x13661366
#define ZSMALLOC_MAGIC    0x58295829
#define DMA_BUF_MAGIC     0x444d4142 /* "DMAB" */
#define DEVMEM_MAGIC      0x454d444d /* "DMEM" */
#define Z3FOLD_MAGIC      0x33
#define PPC_CMM_MAGIC     0xc7571590

#endif /* ifndef KERNEL_DEFS_H */
