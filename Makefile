VMLINUX = vmlinux_$(shell uname -r).h

.PHONY: build
build: vmlinux
	cargo libbpf make

.PHONY: vmlinux
vmlinux: src/bpf/$(VMLINUX) src/bpf/vmlinux.h
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/$(VMLINUX)
	ln -snfr src/bpf/$(VMLINUX) src/bpf/vmlinux.h

.PHONY: install
install:
	cargo install

.PHONY: clean
clean:
	cargo clean

