#ifndef COMPAT_H
#define COMPAT_H

/* Linux 5.14 renames this so let's just define both here.
 * TODO: There may be a better way to do this with BPF CO-RE helpers. */
#define LOCKDOWN_BPF_READ (LOCKDOWN_KPROBES + 1)
#define LOCKDOWN_BPF_READ_KERNEL (LOCKDOWN_KPROBES + 1)

#endif /* ifndef COMPAT_H */
