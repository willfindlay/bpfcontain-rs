// SPDX-License-Identifier: GPL-2
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
 * https://elixir.bootlin.com/linux/v6.10/source/include/uapi/asm-generic/mman-common.h#L10 */
#define PROT_READ   0x1     /* page can be read */
#define PROT_WRITE  0x2     /* page can be written */
#define PROT_EXEC   0x4     /* page can be executed */

/* ========================================================================= *
 * uapi/linux/mman.h                                                         *
 * ========================================================================= */

/* mmap flags
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/mman.h#L8 */
#define MREMAP_MAYMOVE      1
#define MREMAP_FIXED        2
#define MREMAP_DONTUNMAP    4

#define OVERCOMMIT_GUESS    0
#define OVERCOMMIT_ALWAYS   1
#define OVERCOMMIT_NEVER    2

#define MAP_SHARED  0x01        /* Share changes */
#define MAP_PRIVATE 0x02        /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03    /* share + validate extension flags */

/* ========================================================================= *
 * uapi/linux/mman.h                                                         *
 * ========================================================================= */

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/mm.h#L253
 */
#define VM_NONE     0x00000000

#define VM_READ     0x00000001  /* currently active flags */
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004
#define VM_SHARED   0x00000008

/* ========================================================================= *
 * linux/socket.h                                                            *
 * ========================================================================= */

/* Supported address families.
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/socket.h#L175 */
#define AF_UNSPEC   0
#define AF_UNIX     1   /* Unix domain sockets            */
#define AF_LOCAL    1   /* POSIX name for AF_UNIX         */
#define AF_INET     2   /* Internet IP Protocol           */
#define AF_AX25     3   /* Amateur Radio AX.25            */
#define AF_IPX      4   /* Novell IPX                     */
#define AF_APPLETALK    5   /* AppleTalk DDP              */
#define AF_NETROM   6   /* Amateur Radio NET/ROM          */
#define AF_BRIDGE   7   /* Multiprotocol bridge           */
#define AF_ATMPVC   8   /* ATM PVCs                       */
#define AF_X25      9   /* Reserved for X.25 project      */
#define AF_INET6    10  /* IP version 6                   */
#define AF_ROSE     11  /* Amateur Radio X.25 PLP         */
#define AF_DECnet   12  /* Reserved for DECnet project    */
#define AF_NETBEUI  13  /* Reserved for 802.2LLC project  */
#define AF_SECURITY 14  /* Security callback pseudo AF    */
#define AF_KEY      15  /* PF_KEY key management API      */
#define AF_NETLINK  16
#define AF_ROUTE    AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET   17  /* Packet family                  */
#define AF_ASH      18  /* Ash                            */
#define AF_ECONET   19  /* Acorn Econet                   */
#define AF_ATMSVC   20  /* ATM SVCs                       */
#define AF_RDS      21  /* RDS sockets                    */
#define AF_SNA      22  /* Linux SNA Project (nutters!)   */
#define AF_IRDA     23  /* IRDA sockets                   */
#define AF_PPPOX    24  /* PPPoX sockets                  */
#define AF_WANPIPE  25  /* Wanpipe API Sockets            */
#define AF_LLC      26  /* Linux LLC                      */
#define AF_IB       27  /* Native InfiniBand address      */
#define AF_MPLS     28  /* MPLS                           */
#define AF_CAN      29  /* Controller Area Network        */
#define AF_TIPC     30  /* TIPC sockets                   */
#define AF_BLUETOOTH 31  /* Bluetooth sockets             */
#define AF_IUCV     32  /* IUCV sockets                   */
#define AF_RXRPC    33  /* RxRPC sockets                  */
#define AF_ISDN     34  /* mISDN sockets                  */
#define AF_PHONET   35  /* Phonet sockets                 */
#define AF_IEEE802154 36  /* IEEE802154 sockets           */
#define AF_CAIF     37  /* CAIF sockets                   */
#define AF_ALG      38  /* Algorithm sockets              */
#define AF_NFC      39  /* NFC sockets                    */
#define AF_VSOCK    40  /* vSockets                       */
#define AF_KCM      41  /* Kernel Connection Multiplexor  */
#define AF_QIPCRTR  42  /* Qualcomm IPC Router            */
#define AF_SMC      43  /* smc sockets: reserve number for
                         * PF_SMC protocol family that
                         * reuses AF_INET address family
                         */
#define AF_XDP      44  /* XDP sockets          */

#define AF_MAX      45  /* For now.. */

/* ========================================================================= *
 * arch/x86/include/uapi/asm/signal.h                                        *
 * ========================================================================= */

/* Signal numbers TODO: handle other archs
 * https://elixir.bootlin.com/linux/v5.10/source/arch/x86/include/uapi/asm/signal.h#L23
 */
#define SIGHUP       1
#define SIGINT       2
#define SIGQUIT      3
#define SIGILL       4
#define SIGTRAP      5
#define SIGABRT      6
#define SIGIOT       6
#define SIGBUS       7
#define SIGFPE       8
#define SIGKILL      9
#define SIGUSR1     10
#define SIGSEGV     11
#define SIGUSR2     12
#define SIGPIPE     13
#define SIGALRM     14
#define SIGTERM     15
#define SIGSTKFLT   16
#define SIGCHLD     17
#define SIGCONT     18
#define SIGSTOP     19
#define SIGTSTP     20
#define SIGTTIN     21
#define SIGTTOU     22
#define SIGURG      23
#define SIGXCPU     24
#define SIGXFSZ     25
#define SIGVTALRM   26
#define SIGPROF     27
#define SIGWINCH    28
#define SIGIO       29
#define SIGPOLL     SIGIO
#define SIGLOST     29
#define SIGPWR      30
#define SIGSYS      31
#define SIGUNUSED   31

/* ========================================================================= *
 * uapi/linux/capability.h                                                   *
 * ========================================================================= */

/* POSIX capabilities
 * https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/capability.h#L105
 */
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_KILL             5
#define CAP_SETGID           6
#define CAP_SETUID           7
#define CAP_SETPCAP          8
#define CAP_LINUX_IMMUTABLE  9
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_ADMIN        12
#define CAP_NET_RAW          13
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_SYS_MODULE       16
#define CAP_SYS_RAWIO        17
#define CAP_SYS_CHROOT       18
#define CAP_SYS_PTRACE       19
#define CAP_SYS_PACCT        20
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_NICE         23
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_MKNOD            27
#define CAP_LEASE            28
#define CAP_AUDIT_WRITE      29
#define CAP_AUDIT_CONTROL    30
#define CAP_SETFCAP          31
#define CAP_MAC_OVERRIDE     32
#define CAP_MAC_ADMIN        33
#define CAP_SYSLOG           34
#define CAP_WAKE_ALARM       35
#define CAP_BLOCK_SUSPEND    36
#define CAP_AUDIT_READ       37
#define CAP_PERFMON          38
#define CAP_BPF              39
#define CAP_CHECKPOINT_RESTORE 40

#define CAP_LAST_CAP         CAP_CHECKPOINT_RESTORE

#endif /* ifndef KERNEL_DEFS_H */
