VMLINUX = vmlinux_$(shell uname -r).h

.PHONY: build
build: src/bpf/vmlinux.h
	cargo libbpf make
	cargo build

.PHONY: test
test:
	cargo libbpf make
	cargo test -- $(ARGS)

.PHONY: vmlinux
vmlinux: | src/bpf/vmlinux.h

src/bpf/$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/$(VMLINUX)

src/bpf/vmlinux.h: src/bpf/$(VMLINUX)
	ln -snfr src/bpf/$(VMLINUX) src/bpf/vmlinux.h

.PHONY: install
install:
	cargo install

.PHONY: clean
clean:
	cargo clean

