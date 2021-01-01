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

#endif /* ifndef KERNEL_DEFS_H */
