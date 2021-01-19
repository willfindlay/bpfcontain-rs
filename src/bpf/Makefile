VMLINUX = vmlinux_$(shell uname -r).h

.PHONY: vmlinux
vmlinux: vmlinux.h

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux.h: $(VMLINUX)
	ln -snfr $(VMLINUX) vmlinux.h
