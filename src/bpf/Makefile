VMLINUX = $(shell awk -F. '{print $$1$$2}' <<< include/vmlinux_$(shell uname -r)).h

.PHONY: vmlinux
vmlinux: include/vmlinux.h

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

include/vmlinux.h: $(VMLINUX)
	ln -snfr $(VMLINUX) include/vmlinux.h
